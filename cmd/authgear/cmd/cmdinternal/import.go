package cmdinternal

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authgearcmd "github.com/authgear/authgear-server/cmd/authgear/cmd"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type User struct {
	ID            string
	StandardAttrs map[string]interface{}
}

type LoginID struct {
	ID         string
	Type       model.LoginIDKeyType
	UserID     string
	LoginID    string
	Normalized string
	UniqueKey  string
	Claims     map[string]interface{}
}

type Password struct {
	ID           string
	UserID       string
	PasswordHash string
}

var cmdInternalImport = &cobra.Command{
	Use:   "import",
	Short: "Import users",
	RunE: func(cmd *cobra.Command, args []string) error {
		binder := authgearcmd.GetBinder()
		dbURL, err := binder.GetRequiredString(cmd, authgearcmd.ArgDatabaseURL)
		if err != nil {
			return err
		}
		dbSchema, err := binder.GetRequiredString(cmd, authgearcmd.ArgDatabaseSchema)
		if err != nil {
			return err
		}

		inputFile, err := binder.GetRequiredString(cmd, authgearcmd.ArgInputFile)
		if err != nil {
			return err
		}

		appId := args[0]

		context := cmd.Context()

		loggerFactory := log.NewFactory(
			log.LevelDebug,
		)
		logger := loggerFactory.New("importer")
		pool := db.NewPool()
		dbHandle := db.NewHookHandle(
			context,
			pool,
			db.ConnectionOptions{
				DatabaseURL:           dbURL,
				MaxOpenConnection:     1,
				MaxIdleConnection:     1,
				MaxConnectionLifetime: 1800 * time.Second,
				IdleConnectionTimeout: 300 * time.Second,
			},
			loggerFactory,
		)
		appDBHandle := &appdb.Handle{HookHandle: dbHandle}
		appSQLExecutor := appdb.NewSQLExecutor(context, appDBHandle)
		appSQLBuilder := appdb.NewSQLBuilder(&config.DatabaseCredentials{
			DatabaseURL:    dbURL,
			DatabaseSchema: dbSchema,
		})

		sysClock := clock.NewSystemClock()

		inputPathAbs, err := filepath.Abs(inputFile)
		if err != nil {
			return err
		}

		return appDBHandle.WithTx(func() error {
			f, err := os.Open(inputPathAbs)
			if err != nil {
				panic(err)
			}
			defer f.Close()
			csvReader := csv.NewReader(f)
			records, err := csvReader.ReadAll()
			if err != nil {
				panic(err)
			}

			if len(records) < 1 {
				panic("no rows")
			}

			header := records[0]
			idxToKey := map[int]string{}
			for i, h := range header {
				idxToKey[i] = h
			}

			rows := records[1:]

			data := []map[string]string{}
			loginIdSet := map[string]string{}

			for _, row := range rows {
				obj := map[string]string{}
				for colIdx, val := range row {
					key := idxToKey[colIdx]
					obj[key] = val
				}
				data = append(data, obj)
			}

			errs := []error{}

			users := []*User{}
			loginIDs := []*LoginID{}
			passwords := []*Password{}

			for idx, d := range data {
				rowIdx := idx + 2
				logger.WithField("row", rowIdx).Info("import")
				user := &User{ID: uuid.New()}
				stdAttr := map[string]interface{}{}
				if err != nil {
					panic(err)
				}
				if email, ok := d["email"]; ok && email != "" {
					loginId, err := makeLoginID(
						&loginIdSet,
						&stdAttr,
						user.ID,
						email,
						model.LoginIDKeyTypeEmail,
					)
					if err != nil {
						logger.WithError(err).WithFields(logrus.Fields{"row": rowIdx, "email": email}).Info("Ignored")
						// panic(err)
						errs = append(errs, err)
					} else {
						loginIDs = append(loginIDs, loginId)
					}
				}
				if username, ok := d["username"]; ok && username != "" {
					loginId, err := makeLoginID(
						&loginIdSet,
						&stdAttr,
						user.ID,
						username,
						model.LoginIDKeyTypeUsername,
					)
					if err != nil {
						logger.WithError(err).WithFields(logrus.Fields{"row": rowIdx, "username": username}).Info("Ignored")
						// panic(err)
						errs = append(errs, err)
					} else {
						loginIDs = append(loginIDs, loginId)
					}
				}
				if phone, ok := d["phone"]; ok && phone != "" {
					if !strings.HasPrefix(phone, "+") {
						phone = "+852" + phone
					}
					loginId, err := makeLoginID(
						&loginIdSet,
						&stdAttr,
						user.ID,
						phone,
						model.LoginIDKeyTypePhone,
					)
					if err != nil {
						logger.WithError(err).WithFields(logrus.Fields{"row": rowIdx, "phone": phone}).Info("Ignored")
						// panic(err)
						errs = append(errs, err)
					} else {
						loginIDs = append(loginIDs, loginId)
					}
				}
				if pwhash, ok := d["password"]; ok && pwhash != "" {
					pw := &Password{
						ID:           uuid.New(),
						UserID:       user.ID,
						PasswordHash: pwhash,
					}
					passwords = append(passwords, pw)
				}
				user.StandardAttrs = stdAttr
				users = append(users, user)
			}

			err = createUsers(logger, appSQLBuilder.WithAppID(appId), appSQLExecutor, sysClock, users)
			if err != nil {
				panic(err)
			}

			err = createLoginIDs(logger, appSQLBuilder.WithAppID(appId), appSQLExecutor, sysClock, loginIDs)
			if err != nil {
				panic(err)
			}

			err = createPasswords(logger, appSQLBuilder.WithAppID(appId), appSQLExecutor, sysClock, passwords)
			if err != nil {
				panic(err)
			}

			return nil
		})

	},
}

func makeLoginID(
	loginIdSet *map[string]string,
	stdAttrs *map[string]interface{},
	userID string, loginID string, typ model.LoginIDKeyType) (*LoginID, error) {
	id := uuid.New()
	truePtr := true
	cfg := &config.LoginIDConfig{}
	config.SetFieldDefaults(cfg)
	cfg.Types.Username.CaseSensitive = &truePtr
	normalizerFactory := &loginid.NormalizerFactory{Config: cfg}
	normalizer := normalizerFactory.NormalizerWithLoginIDType(typ)

	normalized, err := normalizer.Normalize(loginID)
	if err != nil {
		return nil, err
	}
	uniqueKey, err := normalizer.ComputeUniqueKey(normalized)
	if err != nil {
		return nil, err
	}

	if _, ok := (*loginIdSet)[uniqueKey]; ok {
		return nil, fmt.Errorf("duplicated")
	}

	(*loginIdSet)[uniqueKey] = loginID

	c := map[string]interface{}{}
	switch typ {
	case model.LoginIDKeyTypeUsername:
		c["preferred_username"] = loginID
		(*stdAttrs)[stdattrs.PreferredUsername] = loginID
	case model.LoginIDKeyTypeEmail:
		c["email"] = loginID
		(*stdAttrs)[stdattrs.Email] = loginID
	case model.LoginIDKeyTypePhone:
		c["phone_number"] = loginID
		(*stdAttrs)[stdattrs.PhoneNumber] = loginID
	}

	if err != nil {
		return nil, err
	}

	return &LoginID{
		ID:         id,
		Type:       typ,
		UserID:     userID,
		LoginID:    loginID,
		UniqueKey:  uniqueKey,
		Normalized: normalized,
		Claims:     c,
	}, nil

}

var BATCH_COUNT = 3000

func createUsers(
	logger *log.Logger,
	SQLBuilder *appdb.SQLBuilderApp,
	SQLExecutor *appdb.SQLExecutor,
	clk clock.Clock,
	users []*User) error {
	now := clk.NowUTC()

	if len(users) == 0 {
		return nil
	}

	batches := [][]*User{}
	idx := 0
	for idx < (len(users)) {
		endIdx := idx + BATCH_COUNT
		if endIdx > (len(users)) {
			endIdx = len(users)
		}
		batch := users[idx:endIdx]
		batches = append(batches, batch)
		idx = endIdx
	}

	for idx, batch := range batches {
		logger.
			WithField("batch", idx).
			WithField("count", len(batch)).
			Info("Inserting user")
		q := SQLBuilder.
			Insert(SQLBuilder.TableName("_auth_user")).
			Columns(
				"id",
				"created_at",
				"updated_at",
				"login_at",
				"last_login_at",
				"is_disabled",
				"disable_reason",
				"is_deactivated",
				"delete_at",
				"is_anonymized",
				"anonymize_at",
				"standard_attributes",
				"custom_attributes",
			)
		for _, r := range batch {
			stdAttrs := r.StandardAttrs
			if stdAttrs == nil {
				stdAttrs = make(map[string]interface{})
			}

			stdAttrsBytes, err := json.Marshal(stdAttrs)
			if err != nil {
				return err
			}

			customAttrs := make(map[string]interface{})

			customAttrsBytes, err := json.Marshal(customAttrs)
			if err != nil {
				return err
			}
			q = q.Values(
				r.ID,
				now,
				now,
				nil,
				nil,
				false,
				nil,
				false,
				nil,
				false,
				nil,
				stdAttrsBytes,
				customAttrsBytes,
			)
		}
		_, err := SQLExecutor.ExecWith(q)
		if err != nil {
			return err
		}
	}
	return nil
}

func createLoginIDs(
	logger *log.Logger,
	SQLBuilder *appdb.SQLBuilderApp,
	SQLExecutor *appdb.SQLExecutor,
	clk clock.Clock,
	loginIDs []*LoginID) error {
	now := clk.NowUTC()

	if len(loginIDs) == 0 {
		return nil
	}

	batches := [][]*LoginID{}
	idx := 0
	for idx < (len(loginIDs)) {
		endIdx := idx + BATCH_COUNT
		if endIdx > (len(loginIDs)) {
			endIdx = len(loginIDs)
		}
		batch := loginIDs[idx:endIdx]
		batches = append(batches, batch)
		idx = endIdx
	}

	for idx, batch := range batches {
		logger.
			WithField("batch", idx).
			WithField("count", len(batch)).
			Info("Inserting login ids")
		authIdentityQ := SQLBuilder.
			Insert(SQLBuilder.TableName("_auth_identity")).
			Columns(
				"id",
				"type",
				"user_id",
				"created_at",
				"updated_at",
			)
		authIdentifyLoginIDQ := SQLBuilder.
			Insert(SQLBuilder.TableName("_auth_identity_login_id")).
			Columns(
				"id",
				"login_id_key",
				"login_id_type",
				"login_id",
				"original_login_id",
				"unique_key",
				"claims",
			)
		for _, r := range batch {
			authIdentityQ = authIdentityQ.
				Values(
					r.ID,
					model.IdentityTypeLoginID,
					r.UserID,
					now,
					now,
				)
			claims, err := json.Marshal(r.Claims)
			if err != nil {
				return err
			}
			authIdentifyLoginIDQ = authIdentifyLoginIDQ.Values(
				r.ID,
				string(r.Type),
				string(r.Type),
				r.Normalized,
				r.LoginID,
				r.UniqueKey,
				claims,
			)
		}
		_, err := SQLExecutor.ExecWith(authIdentityQ)
		if err != nil {
			return err
		}
		_, err = SQLExecutor.ExecWith(authIdentifyLoginIDQ)
		if err != nil {
			return err
		}

	}

	return nil
}

func createPasswords(
	logger *log.Logger,
	SQLBuilder *appdb.SQLBuilderApp,
	SQLExecutor *appdb.SQLExecutor,
	clk clock.Clock,
	passwords []*Password) error {
	now := clk.NowUTC()
	if len(passwords) == 0 {
		return nil
	}

	batches := [][]*Password{}
	idx := 0
	for idx < (len(passwords)) {
		endIdx := idx + BATCH_COUNT
		if endIdx > (len(passwords)) {
			endIdx = len(passwords)
		}
		batch := passwords[idx:endIdx]
		batches = append(batches, batch)
		idx = endIdx
	}

	for idx, batch := range batches {
		logger.
			WithField("batch", idx).
			WithField("count", len(batch)).
			Info("Inserting passwords")
		authAuthenticatorQ := SQLBuilder.
			Insert(SQLBuilder.TableName("_auth_authenticator")).
			Columns(
				"id",
				"type",
				"user_id",
				"created_at",
				"updated_at",
				"is_default",
				"kind",
			)
		authAuthenticatorPasswordQ := SQLBuilder.
			Insert(SQLBuilder.TableName("_auth_authenticator_password")).
			Columns(
				"id",
				"password_hash",
			)
		for _, r := range batch {
			authAuthenticatorQ = authAuthenticatorQ.
				Values(
					r.ID,
					model.AuthenticatorTypePassword,
					r.UserID,
					now,
					now,
					false,
					model.AuthenticatorKindPrimary,
				)
			authAuthenticatorPasswordQ = authAuthenticatorPasswordQ.Values(
				r.ID,
				r.PasswordHash,
			)
		}

		_, err := SQLExecutor.ExecWith(authAuthenticatorQ)
		if err != nil {
			return err
		}
		_, err = SQLExecutor.ExecWith(authAuthenticatorPasswordQ)
		if err != nil {
			return err
		}
	}
	return nil
}
