package testrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	texttemplate "text/template"

	"github.com/Masterminds/sprig"
	authflowclient "github.com/authgear/authgear-server/e2e/pkg/e2eclient"
	"github.com/authgear/authgear-server/pkg/util/httputil"
)

type TestCase struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
	// Applying focus to a test case will make it the only test case to run,
	// mainly used for debugging new test cases.
	Focus              bool               `yaml:"focus"`
	AuthgearYAMLSource AuthgearYAMLSource `yaml:"authgear.yaml"`
	Steps              []Step             `yaml:"steps"`
	Before             []BeforeHook       `yaml:"before"`
}

func (tc *TestCase) FullName() string {
	return tc.Path + "/" + tc.Name
}

func (tc *TestCase) Run(t *testing.T) {
	t.Logf("running test case: %s\n", tc.Name)

	ctx := context.Background()

	appID := generateAppID()
	cmd := &End2EndCmd{
		AppID:    appID,
		TestCase: *tc,
	}

	// Create project per test case
	err := cmd.CreateConfigSource()
	if err != nil {
		t.Errorf("failed to create config source: %v", err)
		return
	}

	ok := tc.executeBeforeAll(t, cmd)
	if !ok {
		return
	}

	client := authflowclient.NewClient(
		ctx,
		"localhost:4000",
		httputil.HTTPHost(fmt.Sprintf("%s.portal.localhost:4000", appID)),
	)

	var stepResults []StepResult
	var state string

	for i, step := range tc.Steps {
		if step.Name == "" {
			step.Name = fmt.Sprintf("step %d", i+1)
		}

		var result *StepResult
		result, state, ok = tc.executeStep(t, cmd, client, appID, stepResults, state, step)
		if !ok {
			return
		}

		stepResults = append(stepResults, *result)
	}
}

// Execute before hooks to prepare fixtures
func (tc *TestCase) executeBeforeAll(t *testing.T, cmd *End2EndCmd) (ok bool) {
	for _, beforeHook := range tc.Before {
		switch beforeHook.Type {
		case BeforeHookTypeUserImport:
			err := cmd.ImportUsers(beforeHook.UserImport)
			if err != nil {
				t.Errorf("failed to import users: %v", err)
				return false
			}
		case BeforeHookTypeCustomSQL:
			err := cmd.ExecuteCustomSQL(beforeHook.CustomSQL.Path)
			if err != nil {
				t.Errorf("failed to execute custom SQL: %v", err)
				return false
			}
		default:
			t.Errorf("unknown before hook type: %s", beforeHook.Type)
			return false
		}
	}

	return true
}

func (tc *TestCase) executeStep(
	t *testing.T,
	cmd *End2EndCmd,
	client *authflowclient.Client,
	appID string,
	prevSteps []StepResult,
	state string,
	step Step,
) (result *StepResult, nextState string, ok bool) {
	var flowResponse *authflowclient.FlowResponse
	var flowErr error

	switch step.Action {
	case StepActionCreate:
		var flowReference authflowclient.FlowReference
		err := json.Unmarshal([]byte(step.Input), &flowReference)
		if err != nil {
			t.Errorf("failed to parse input in '%s': %v\n", step.Name, err)
			return
		}

		flowResponse, flowErr = client.Create(flowReference, "")

	case StepActionInput:
		fallthrough
	default:
		if len(prevSteps) == 0 {
			t.Errorf("no previous step result in '%s'", step.Name)
			return
		}

		lastStep := prevSteps[len(prevSteps)-1]
		input, ok := prepareInput(t, cmd, lastStep, step.Input)
		if !ok {
			return nil, state, false
		}

		flowResponse, flowErr = client.Input(nil, nil, state, input)
	}

	if step.Output != nil {
		ok := validateOutput(t, step, flowResponse, flowErr)
		if !ok {
			return nil, state, false
		}
	}

	nextState = state
	if flowResponse != nil {
		nextState = flowResponse.StateToken
	}

	result = &StepResult{
		Result: flowResponse,
		Error:  flowErr,
	}

	return result, nextState, true
}

func prepareInput(t *testing.T, cmd *End2EndCmd, prev StepResult, input string) (prepared map[string]interface{}, ok bool) {
	tmpl := texttemplate.New("")
	tmpl.Funcs(makeTemplateFuncMap(cmd))

	_, err := tmpl.Parse(input)
	if err != nil {
		t.Errorf("failed to parse input: %v\n", err)
		return nil, false
	}

	data := make(map[string]interface{})
	data["Prev"] = prev

	var buf strings.Builder
	err = tmpl.Execute(&buf, data)
	if err != nil {
		t.Errorf("failed to execute input: %v\n", err)
		return nil, false
	}

	var inputMap map[string]interface{}
	err = json.Unmarshal([]byte(buf.String()), &inputMap)
	if err != nil {
		t.Errorf("failed to parse input: %v\n", err)
		return nil, false
	}

	return inputMap, true
}

func makeTemplateFuncMap(cmd *End2EndCmd) texttemplate.FuncMap {
	templateFuncMap := sprig.HermeticHtmlFuncMap()
	templateFuncMap["linkOTPCode"] = func(claimName string, claimValue string) string {
		otpCode, err := cmd.GetLinkOTPCodeByClaim(claimName, claimValue)
		if err != nil {
			panic(err)
		}
		return otpCode
	}
	return templateFuncMap
}

func validateOutput(t *testing.T, step Step, flowResponse *authflowclient.FlowResponse, flowErr error) (ok bool) {
	errorViolations, resultViolations, err := MatchOutput(*step.Output, flowResponse, flowErr)
	if err != nil {
		t.Errorf("failed to match output in '%s': %v\n", step.Name, err)
		t.Errorf("  result: %v\n", flowResponse)
		t.Errorf("  error: %v\n", flowErr)
		return false
	}

	if len(errorViolations) > 0 {
		t.Errorf("error output mismatch in '%s': %v\n", step.Name, flowErr)
		for _, violation := range errorViolations {
			t.Errorf("  %s: %s. Expected %s, got %s", violation.Path, violation.Message, violation.Expected, violation.Actual)
		}
		return false
	}

	if len(resultViolations) > 0 {
		t.Errorf("result output mismatch in '%s': %v\n", step.Name, flowResponse)
		for _, violation := range resultViolations {
			t.Errorf("  %s: %s. Expected %s, got %s", violation.Path, violation.Message, violation.Expected, violation.Actual)
		}
		return false
	}

	return true
}

func generateAppID() string {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(id)
}