package cmdinternal

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	authgearcmd "github.com/authgear/authgear-server/cmd/authgear/cmd"
	"github.com/authgear/authgear-server/pkg/api/model"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity/loginid"
	"github.com/authgear/authgear-server/pkg/lib/authn/stdattrs"
	"github.com/authgear/authgear-server/pkg/lib/authn/user"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/db"
	"github.com/authgear/authgear-server/pkg/lib/infra/db/appdb"
	"github.com/authgear/authgear-server/pkg/util/clock"
	"github.com/authgear/authgear-server/pkg/util/log"
	"github.com/authgear/authgear-server/pkg/util/uuid"
	"github.com/spf13/cobra"
)

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

		userStore := user.Store{
			SQLBuilder:  appSQLBuilder.WithAppID(appId),
			SQLExecutor: appSQLExecutor,
			Clock:       sysClock,
		}

		userRawCommands := user.RawCommands{
			Clock: sysClock,
			Store: &userStore,
		}

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

			for _, row := range rows {
				obj := map[string]string{}
				for colIdx, val := range row {
					key := idxToKey[colIdx]
					obj[key] = val
				}
				data = append(data, obj)
			}

			for _, d := range data {
				user, err := userRawCommands.Create(uuid.New())
				stdAttr := map[string]interface{}{}
				if err != nil {
					panic(err)
				}
				if username, ok := d["username"]; ok && username != "" {
					err := createLoginID(
						appSQLBuilder.WithAppID(appId),
						appSQLExecutor,
						sysClock,
						&stdAttr,
						user.ID,
						username,
						model.LoginIDKeyTypeUsername,
					)
					if err != nil {
						panic(err)
					}
				}
				if email, ok := d["email"]; ok && email != "" {
					err := createLoginID(
						appSQLBuilder.WithAppID(appId),
						appSQLExecutor,
						sysClock,
						&stdAttr,
						user.ID,
						email,
						model.LoginIDKeyTypeEmail,
					)
					if err != nil {
						panic(err)
					}
				}
				if phone, ok := d["phone"]; ok && phone != "" {
					err := createLoginID(
						appSQLBuilder.WithAppID(appId),
						appSQLExecutor,
						sysClock,
						&stdAttr,
						user.ID,
						phone,
						model.LoginIDKeyTypePhone,
					)
					if err != nil {
						panic(err)
					}
				}
				if pwhash, ok := d["password"]; ok && pwhash != "" {
					err := createPassword(
						appSQLBuilder.WithAppID(appId),
						appSQLExecutor,
						sysClock,
						user.ID,
						pwhash,
					)
					if err != nil {
						panic(err)
					}
				}
				err = userStore.UpdateStandardAttributes(user.ID, stdAttr)
				if err != nil {
					panic(err)
				}
			}
			return nil
		})

	},
}

func createLoginID(
	SQLBuilder *appdb.SQLBuilderApp,
	SQLExecutor *appdb.SQLExecutor,
	clk clock.Clock,
	stdAttrs *map[string]interface{},
	userID string, loginID string, typ model.LoginIDKeyType) error {
	now := clk.NowUTC()
	id := uuid.New()
	cfg := &config.LoginIDConfig{}
	config.SetFieldDefaults(cfg)
	normalizerFactory := &loginid.NormalizerFactory{Config: cfg}
	normalizer := normalizerFactory.NormalizerWithLoginIDType(typ)

	builder := SQLBuilder.
		Insert(SQLBuilder.TableName("_auth_identity")).
		Columns(
			"id",
			"type",
			"user_id",
			"created_at",
			"updated_at",
		).
		Values(
			id,
			model.IdentityTypeLoginID,
			userID,
			now,
			now,
		)

	_, err := SQLExecutor.ExecWith(builder)
	if err != nil {
		return err
	}

	c := map[string]string{}
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

	claims, err := json.Marshal(map[string]string{
		"preferred_username": loginID,
	})
	if err != nil {
		return err
	}

	normalized, err := normalizer.Normalize(loginID)
	if err != nil {
		return err
	}
	uniqueKey, err := normalizer.ComputeUniqueKey(normalized)
	if err != nil {
		return err
	}

	q := SQLBuilder.
		Insert(SQLBuilder.TableName("_auth_identity_login_id")).
		Columns(
			"id",
			"login_id_key",
			"login_id_type",
			"login_id",
			"original_login_id",
			"unique_key",
			"claims",
		).
		Values(
			id,
			string(typ),
			string(typ),
			normalized,
			loginID,
			uniqueKey,
			claims,
		)

	_, err = SQLExecutor.ExecWith(q)
	if err != nil {
		return err
	}

	return nil
}

func createPassword(
	SQLBuilder *appdb.SQLBuilderApp,
	SQLExecutor *appdb.SQLExecutor,
	clk clock.Clock,
	userID string, pwHash string) error {
	id := uuid.New()
	now := clk.NowUTC()
	q := SQLBuilder.
		Insert(SQLBuilder.TableName("_auth_authenticator")).
		Columns(
			"id",
			"type",
			"user_id",
			"created_at",
			"updated_at",
			"is_default",
			"kind",
		).
		Values(
			id,
			model.AuthenticatorTypePassword,
			userID,
			now,
			now,
			false,
			model.AuthenticatorKindPrimary,
		)
	_, err := SQLExecutor.ExecWith(q)
	if err != nil {
		return err
	}

	q = SQLBuilder.
		Insert(SQLBuilder.TableName("_auth_authenticator_password")).
		Columns(
			"id",
			"password_hash",
		).
		Values(
			id,
			pwHash,
		)
	_, err = SQLExecutor.ExecWith(q)
	if err != nil {
		return err
	}

	return nil
}
