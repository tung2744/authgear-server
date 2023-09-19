package declarative

import (
	"encoding/json"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/authgear/authgear-server/pkg/lib/config"
)

func TestInputSchemaStepIdentify(t *testing.T) {
	Convey("InputSchemaStepIdentify", t, func() {
		test := func(s *InputSchemaStepIdentify, expected string) {
			b := s.SchemaBuilder()
			bytes, err := json.Marshal(b)
			So(err, ShouldBeNil)
			So(string(bytes), ShouldEqualJSON, expected)
		}

		test(&InputSchemaStepIdentify{
			Candidates: []IdentificationCandidate{
				{
					Identification: config.AuthenticationFlowIdentificationEmail,
				},
				{
					Identification: config.AuthenticationFlowIdentificationPhone,
				},
				{
					Identification: config.AuthenticationFlowIdentificationUsername,
				},
				{
					Identification: config.AuthenticationFlowIdentificationOAuth,
					Alias:          "google",
				},
				{
					Identification: config.AuthenticationFlowIdentificationOAuth,
					Alias:          "wechat_mobile",
					WechatAppType:  config.OAuthSSOWeChatAppTypeMobile,
				},
			},
		}, `
{
    "oneOf": [
        {
            "properties": {
                "identification": {
                    "const": "email"
                },
                "login_id": {
                    "type": "string"
                }
            },
            "required": [
                "identification",
                "login_id"
            ]
        },
        {
            "properties": {
                "identification": {
                    "const": "phone"
                },
                "login_id": {
                    "type": "string"
                }
            },
            "required": [
                "identification",
                "login_id"
            ]
        },
        {
            "properties": {
                "identification": {
                    "const": "username"
                },
                "login_id": {
                    "type": "string"
                }
            },
            "required": [
                "identification",
                "login_id"
            ]
        },
        {
            "properties": {
                "alias": {
                    "const": "google",
                    "type": "string"
                },
                "identification": {
                    "const": "oauth"
                },
                "redirect_uri": {
                    "type": "string",
		    "format": "uri"
                },
                "state": {
                    "type": "string"
                }
            },
            "required": [
                "identification",
                "redirect_uri",
                "state",
                "alias"
            ]
        },
        {
            "properties": {
                "alias": {
                    "const": "wechat_mobile",
                    "type": "string"
                },
                "identification": {
                    "const": "oauth"
                },
                "redirect_uri": {
                    "type": "string",
		    "format": "uri"
                },
                "state": {
                    "type": "string"
                }
            },
            "required": [
                "identification",
                "redirect_uri",
                "state",
                "alias"
            ]
        }
    ],
    "type": "object"
}
		`)
	})
}