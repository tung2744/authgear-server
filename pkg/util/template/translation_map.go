package template

import (
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"text/template/parse"

	"github.com/authgear/authgear-server/pkg/util/messageformat"
)

type TranslationMap struct {
	validator *Validator
	items     map[string]*parse.Tree
}

func (t *TranslationMap) HasKey(key string) bool {
	tree, ok := t.items[key]
	return ok && !messageformat.IsEmptyParseTree(tree)
}

func (t *TranslationMap) RenderText(key string, args interface{}) (string, error) {
	tree, ok := t.items[key]
	if !ok {
		return "", fmt.Errorf("%w: translation key not found: %s", ErrNotFound, key)
	}

	tpl := texttemplate.New("")
	tpl.Funcs(DefaultFuncMap)
	_, err := tpl.AddParseTree("translation", tree)
	if err != nil {
		return "", fmt.Errorf("template: failed to construct template: %w", err)
	}
	tpl = tpl.Lookup("translation")

	err = t.validator.ValidateTextTemplate(tpl)
	if err != nil {
		return "", fmt.Errorf("template: failed to validate template: %w", err)
	}

	var buf strings.Builder
	err = tpl.Execute(NewLimitWriter(&buf), args)
	if err != nil {
		return "", fmt.Errorf("template: failed to render template: %w", err)
	}

	return buf.String(), nil
}

func (t *TranslationMap) RenderHTML(key string, args interface{}) (string, error) {
	tree, ok := t.items[key]
	if !ok {
		return "", fmt.Errorf("%w: translation key not found: %s", ErrNotFound, key)
	}

	tpl := htmltemplate.New("")
	tpl.Funcs(DefaultFuncMap)
	_, err := tpl.AddParseTree("translation", tree)
	if err != nil {
		return "", fmt.Errorf("template: failed to construct template: %w", err)
	}
	tpl = tpl.Lookup("translation")

	err = t.validator.ValidateHTMLTemplate(tpl)
	if err != nil {
		return "", fmt.Errorf("template: failed to validate template: %w", err)
	}

	var buf strings.Builder
	err = tpl.Execute(NewLimitWriter(&buf), args)
	if err != nil {
		return "", fmt.Errorf("template: failed to render template: %w", err)
	}

	return buf.String(), nil
}
