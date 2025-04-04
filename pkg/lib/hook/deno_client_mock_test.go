// Code generated by MockGen. DO NOT EDIT.
// Source: deno_client.go

// Package hook is a generated GoMock package.
package hook

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockSyncDenoClient is a mock of SyncDenoClient interface.
type MockSyncDenoClient struct {
	ctrl     *gomock.Controller
	recorder *MockSyncDenoClientMockRecorder
}

// MockSyncDenoClientMockRecorder is the mock recorder for MockSyncDenoClient.
type MockSyncDenoClientMockRecorder struct {
	mock *MockSyncDenoClient
}

// NewMockSyncDenoClient creates a new mock instance.
func NewMockSyncDenoClient(ctrl *gomock.Controller) *MockSyncDenoClient {
	mock := &MockSyncDenoClient{ctrl: ctrl}
	mock.recorder = &MockSyncDenoClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSyncDenoClient) EXPECT() *MockSyncDenoClientMockRecorder {
	return m.recorder
}

// Run mocks base method.
func (m *MockSyncDenoClient) Run(ctx context.Context, script string, input interface{}) (interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Run", ctx, script, input)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Run indicates an expected call of Run.
func (mr *MockSyncDenoClientMockRecorder) Run(ctx, script, input interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockSyncDenoClient)(nil).Run), ctx, script, input)
}

// MockAsyncDenoClient is a mock of AsyncDenoClient interface.
type MockAsyncDenoClient struct {
	ctrl     *gomock.Controller
	recorder *MockAsyncDenoClientMockRecorder
}

// MockAsyncDenoClientMockRecorder is the mock recorder for MockAsyncDenoClient.
type MockAsyncDenoClientMockRecorder struct {
	mock *MockAsyncDenoClient
}

// NewMockAsyncDenoClient creates a new mock instance.
func NewMockAsyncDenoClient(ctrl *gomock.Controller) *MockAsyncDenoClient {
	mock := &MockAsyncDenoClient{ctrl: ctrl}
	mock.recorder = &MockAsyncDenoClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAsyncDenoClient) EXPECT() *MockAsyncDenoClientMockRecorder {
	return m.recorder
}

// Run mocks base method.
func (m *MockAsyncDenoClient) Run(ctx context.Context, script string, input interface{}) (interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Run", ctx, script, input)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Run indicates an expected call of Run.
func (mr *MockAsyncDenoClientMockRecorder) Run(ctx, script, input interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockAsyncDenoClient)(nil).Run), ctx, script, input)
}
