// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/wolfeidau/cloudtrail-log-processor/internal/snsevents (interfaces: UploaderAPI)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	s3manager "github.com/aws/aws-sdk-go/service/s3/s3manager"
	gomock "github.com/golang/mock/gomock"
)

// MockUploaderAPI is a mock of UploaderAPI interface.
type MockUploaderAPI struct {
	ctrl     *gomock.Controller
	recorder *MockUploaderAPIMockRecorder
}

// MockUploaderAPIMockRecorder is the mock recorder for MockUploaderAPI.
type MockUploaderAPIMockRecorder struct {
	mock *MockUploaderAPI
}

// NewMockUploaderAPI creates a new mock instance.
func NewMockUploaderAPI(ctrl *gomock.Controller) *MockUploaderAPI {
	mock := &MockUploaderAPI{ctrl: ctrl}
	mock.recorder = &MockUploaderAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUploaderAPI) EXPECT() *MockUploaderAPIMockRecorder {
	return m.recorder
}

// UploadWithContext mocks base method.
func (m *MockUploaderAPI) UploadWithContext(arg0 context.Context, arg1 *s3manager.UploadInput, arg2 ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UploadWithContext", varargs...)
	ret0, _ := ret[0].(*s3manager.UploadOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UploadWithContext indicates an expected call of UploadWithContext.
func (mr *MockUploaderAPIMockRecorder) UploadWithContext(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UploadWithContext", reflect.TypeOf((*MockUploaderAPI)(nil).UploadWithContext), varargs...)
}
