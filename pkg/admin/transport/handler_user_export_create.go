package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/authgear/authgear-server/pkg/api"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/lib/infra/redisqueue"
	"github.com/authgear/authgear-server/pkg/lib/userexport"
	"github.com/authgear/authgear-server/pkg/util/httproute"
	"github.com/authgear/authgear-server/pkg/util/httputil"
)

func ConfigureUserExportCreateRoute(route httproute.Route) httproute.Route {
	return route.WithMethods("POST").
		WithPathPattern("/_api/admin/users/export")
}

type UserExportCreateHandlerCloudStorage interface {
	PresignGetObject(name string, expire time.Duration) (*url.URL, error)
}

type UserExportCreateProducer interface {
	NewTask(appID string, input json.RawMessage, taskIDPrefix string) *redisqueue.Task
	EnqueueTask(ctx context.Context, task *redisqueue.Task) error
}

type UserExportCreateHandler struct {
	AppID        config.AppID
	JSON         JSONResponseWriter
	UserExports  UserExportCreateProducer
	CloudStorage UserExportCreateHandlerCloudStorage
}

func (h *UserExportCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.handle(w, r)
	if err != nil {
		h.JSON.WriteResponse(w, &api.Response{Error: err})
		return
	}
}

func (h *UserExportCreateHandler) handle(w http.ResponseWriter, r *http.Request) error {
	if h.CloudStorage == nil {
		return userexport.ErrUserExportDisabled
	}

	var request userexport.Request
	err := httputil.BindJSONBody(r, w, userexport.RequestSchema.Validator(), &request)
	if err != nil {
		return err
	}

	rawMessage, err := json.Marshal(request)
	if err != nil {
		return err
	}

	task := h.UserExports.NewTask(string(h.AppID), rawMessage, "userexport")
	err = h.UserExports.EnqueueTask(r.Context(), task)
	if err != nil {
		return err
	}

	response, err := userexport.NewResponseFromTask(task)
	if err != nil {
		return err
	}

	h.JSON.WriteResponse(w, &api.Response{
		Result: response,
	})
	return nil
}