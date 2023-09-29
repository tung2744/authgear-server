// Code generated by MockGen. DO NOT EDIT.
// Source: authflow_controller.go

// Package webapp is a generated GoMock package.
package webapp

import (
	json "encoding/json"
	http "net/http"
	reflect "reflect"

	webapp "github.com/authgear/authgear-server/pkg/auth/webapp"
	authenticationflow "github.com/authgear/authgear-server/pkg/lib/authenticationflow"
	config "github.com/authgear/authgear-server/pkg/lib/config"
	oauthsession "github.com/authgear/authgear-server/pkg/lib/oauth/oauthsession"
	oidc "github.com/authgear/authgear-server/pkg/lib/oauth/oidc"
	protocol "github.com/authgear/authgear-server/pkg/lib/oauth/protocol"
	httputil "github.com/authgear/authgear-server/pkg/util/httputil"
	gomock "github.com/golang/mock/gomock"
)

// MockAuthflowControllerCookieManager is a mock of AuthflowControllerCookieManager interface.
type MockAuthflowControllerCookieManager struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerCookieManagerMockRecorder
}

// MockAuthflowControllerCookieManagerMockRecorder is the mock recorder for MockAuthflowControllerCookieManager.
type MockAuthflowControllerCookieManagerMockRecorder struct {
	mock *MockAuthflowControllerCookieManager
}

// NewMockAuthflowControllerCookieManager creates a new mock instance.
func NewMockAuthflowControllerCookieManager(ctrl *gomock.Controller) *MockAuthflowControllerCookieManager {
	mock := &MockAuthflowControllerCookieManager{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerCookieManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerCookieManager) EXPECT() *MockAuthflowControllerCookieManagerMockRecorder {
	return m.recorder
}

// ClearCookie mocks base method.
func (m *MockAuthflowControllerCookieManager) ClearCookie(def *httputil.CookieDef) *http.Cookie {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClearCookie", def)
	ret0, _ := ret[0].(*http.Cookie)
	return ret0
}

// ClearCookie indicates an expected call of ClearCookie.
func (mr *MockAuthflowControllerCookieManagerMockRecorder) ClearCookie(def interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClearCookie", reflect.TypeOf((*MockAuthflowControllerCookieManager)(nil).ClearCookie), def)
}

// GetCookie mocks base method.
func (m *MockAuthflowControllerCookieManager) GetCookie(r *http.Request, def *httputil.CookieDef) (*http.Cookie, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCookie", r, def)
	ret0, _ := ret[0].(*http.Cookie)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCookie indicates an expected call of GetCookie.
func (mr *MockAuthflowControllerCookieManagerMockRecorder) GetCookie(r, def interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCookie", reflect.TypeOf((*MockAuthflowControllerCookieManager)(nil).GetCookie), r, def)
}

// ValueCookie mocks base method.
func (m *MockAuthflowControllerCookieManager) ValueCookie(def *httputil.CookieDef, value string) *http.Cookie {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValueCookie", def, value)
	ret0, _ := ret[0].(*http.Cookie)
	return ret0
}

// ValueCookie indicates an expected call of ValueCookie.
func (mr *MockAuthflowControllerCookieManagerMockRecorder) ValueCookie(def, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValueCookie", reflect.TypeOf((*MockAuthflowControllerCookieManager)(nil).ValueCookie), def, value)
}

// MockAuthflowControllerSessionStore is a mock of AuthflowControllerSessionStore interface.
type MockAuthflowControllerSessionStore struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerSessionStoreMockRecorder
}

// MockAuthflowControllerSessionStoreMockRecorder is the mock recorder for MockAuthflowControllerSessionStore.
type MockAuthflowControllerSessionStoreMockRecorder struct {
	mock *MockAuthflowControllerSessionStore
}

// NewMockAuthflowControllerSessionStore creates a new mock instance.
func NewMockAuthflowControllerSessionStore(ctrl *gomock.Controller) *MockAuthflowControllerSessionStore {
	mock := &MockAuthflowControllerSessionStore{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerSessionStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerSessionStore) EXPECT() *MockAuthflowControllerSessionStoreMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockAuthflowControllerSessionStore) Create(session *webapp.Session) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", session)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockAuthflowControllerSessionStoreMockRecorder) Create(session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockAuthflowControllerSessionStore)(nil).Create), session)
}

// Delete mocks base method.
func (m *MockAuthflowControllerSessionStore) Delete(id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockAuthflowControllerSessionStoreMockRecorder) Delete(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockAuthflowControllerSessionStore)(nil).Delete), id)
}

// Get mocks base method.
func (m *MockAuthflowControllerSessionStore) Get(id string) (*webapp.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", id)
	ret0, _ := ret[0].(*webapp.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockAuthflowControllerSessionStoreMockRecorder) Get(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockAuthflowControllerSessionStore)(nil).Get), id)
}

// Update mocks base method.
func (m *MockAuthflowControllerSessionStore) Update(session *webapp.Session) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", session)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockAuthflowControllerSessionStoreMockRecorder) Update(session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockAuthflowControllerSessionStore)(nil).Update), session)
}

// MockAuthflowControllerAuthflowService is a mock of AuthflowControllerAuthflowService interface.
type MockAuthflowControllerAuthflowService struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerAuthflowServiceMockRecorder
}

// MockAuthflowControllerAuthflowServiceMockRecorder is the mock recorder for MockAuthflowControllerAuthflowService.
type MockAuthflowControllerAuthflowServiceMockRecorder struct {
	mock *MockAuthflowControllerAuthflowService
}

// NewMockAuthflowControllerAuthflowService creates a new mock instance.
func NewMockAuthflowControllerAuthflowService(ctrl *gomock.Controller) *MockAuthflowControllerAuthflowService {
	mock := &MockAuthflowControllerAuthflowService{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerAuthflowServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerAuthflowService) EXPECT() *MockAuthflowControllerAuthflowServiceMockRecorder {
	return m.recorder
}

// CreateNewFlow mocks base method.
func (m *MockAuthflowControllerAuthflowService) CreateNewFlow(intent authenticationflow.PublicFlow, sessionOptions *authenticationflow.SessionOptions) (*authenticationflow.ServiceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNewFlow", intent, sessionOptions)
	ret0, _ := ret[0].(*authenticationflow.ServiceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateNewFlow indicates an expected call of CreateNewFlow.
func (mr *MockAuthflowControllerAuthflowServiceMockRecorder) CreateNewFlow(intent, sessionOptions interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNewFlow", reflect.TypeOf((*MockAuthflowControllerAuthflowService)(nil).CreateNewFlow), intent, sessionOptions)
}

// FeedInput mocks base method.
func (m *MockAuthflowControllerAuthflowService) FeedInput(stateToken string, rawMessage json.RawMessage) (*authenticationflow.ServiceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FeedInput", stateToken, rawMessage)
	ret0, _ := ret[0].(*authenticationflow.ServiceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FeedInput indicates an expected call of FeedInput.
func (mr *MockAuthflowControllerAuthflowServiceMockRecorder) FeedInput(stateToken, rawMessage interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FeedInput", reflect.TypeOf((*MockAuthflowControllerAuthflowService)(nil).FeedInput), stateToken, rawMessage)
}

// Get mocks base method.
func (m *MockAuthflowControllerAuthflowService) Get(stateToken string) (*authenticationflow.ServiceOutput, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", stateToken)
	ret0, _ := ret[0].(*authenticationflow.ServiceOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockAuthflowControllerAuthflowServiceMockRecorder) Get(stateToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockAuthflowControllerAuthflowService)(nil).Get), stateToken)
}

// MockAuthflowControllerOAuthSessionService is a mock of AuthflowControllerOAuthSessionService interface.
type MockAuthflowControllerOAuthSessionService struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerOAuthSessionServiceMockRecorder
}

// MockAuthflowControllerOAuthSessionServiceMockRecorder is the mock recorder for MockAuthflowControllerOAuthSessionService.
type MockAuthflowControllerOAuthSessionServiceMockRecorder struct {
	mock *MockAuthflowControllerOAuthSessionService
}

// NewMockAuthflowControllerOAuthSessionService creates a new mock instance.
func NewMockAuthflowControllerOAuthSessionService(ctrl *gomock.Controller) *MockAuthflowControllerOAuthSessionService {
	mock := &MockAuthflowControllerOAuthSessionService{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerOAuthSessionServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerOAuthSessionService) EXPECT() *MockAuthflowControllerOAuthSessionServiceMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockAuthflowControllerOAuthSessionService) Get(entryID string) (*oauthsession.Entry, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", entryID)
	ret0, _ := ret[0].(*oauthsession.Entry)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockAuthflowControllerOAuthSessionServiceMockRecorder) Get(entryID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockAuthflowControllerOAuthSessionService)(nil).Get), entryID)
}

// MockAuthflowControllerUIInfoResolver is a mock of AuthflowControllerUIInfoResolver interface.
type MockAuthflowControllerUIInfoResolver struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerUIInfoResolverMockRecorder
}

// MockAuthflowControllerUIInfoResolverMockRecorder is the mock recorder for MockAuthflowControllerUIInfoResolver.
type MockAuthflowControllerUIInfoResolverMockRecorder struct {
	mock *MockAuthflowControllerUIInfoResolver
}

// NewMockAuthflowControllerUIInfoResolver creates a new mock instance.
func NewMockAuthflowControllerUIInfoResolver(ctrl *gomock.Controller) *MockAuthflowControllerUIInfoResolver {
	mock := &MockAuthflowControllerUIInfoResolver{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerUIInfoResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerUIInfoResolver) EXPECT() *MockAuthflowControllerUIInfoResolverMockRecorder {
	return m.recorder
}

// ResolveForUI mocks base method.
func (m *MockAuthflowControllerUIInfoResolver) ResolveForUI(r protocol.AuthorizationRequest) (*oidc.UIInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveForUI", r)
	ret0, _ := ret[0].(*oidc.UIInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveForUI indicates an expected call of ResolveForUI.
func (mr *MockAuthflowControllerUIInfoResolverMockRecorder) ResolveForUI(r interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveForUI", reflect.TypeOf((*MockAuthflowControllerUIInfoResolver)(nil).ResolveForUI), r)
}

// MockAuthflowControllerOAuthClientResolver is a mock of AuthflowControllerOAuthClientResolver interface.
type MockAuthflowControllerOAuthClientResolver struct {
	ctrl     *gomock.Controller
	recorder *MockAuthflowControllerOAuthClientResolverMockRecorder
}

// MockAuthflowControllerOAuthClientResolverMockRecorder is the mock recorder for MockAuthflowControllerOAuthClientResolver.
type MockAuthflowControllerOAuthClientResolverMockRecorder struct {
	mock *MockAuthflowControllerOAuthClientResolver
}

// NewMockAuthflowControllerOAuthClientResolver creates a new mock instance.
func NewMockAuthflowControllerOAuthClientResolver(ctrl *gomock.Controller) *MockAuthflowControllerOAuthClientResolver {
	mock := &MockAuthflowControllerOAuthClientResolver{ctrl: ctrl}
	mock.recorder = &MockAuthflowControllerOAuthClientResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthflowControllerOAuthClientResolver) EXPECT() *MockAuthflowControllerOAuthClientResolverMockRecorder {
	return m.recorder
}

// ResolveClient mocks base method.
func (m *MockAuthflowControllerOAuthClientResolver) ResolveClient(clientID string) *config.OAuthClientConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveClient", clientID)
	ret0, _ := ret[0].(*config.OAuthClientConfig)
	return ret0
}

// ResolveClient indicates an expected call of ResolveClient.
func (mr *MockAuthflowControllerOAuthClientResolverMockRecorder) ResolveClient(clientID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveClient", reflect.TypeOf((*MockAuthflowControllerOAuthClientResolver)(nil).ResolveClient), clientID)
}