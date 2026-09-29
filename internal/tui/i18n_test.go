package tui

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"ssh-mcp/internal/ipc"
)

func TestMessagesCompleteness(t *testing.T) {
	t.Parallel()

	dicts := []struct {
		name string
		msg  *Messages
	}{
		{"messagesZH", messagesZH},
		{"messagesEN", messagesEN},
	}

	for _, d := range dicts {
		t.Run(d.name, func(t *testing.T) {
			val := reflect.ValueOf(d.msg).Elem()
			typ := val.Type()

			for i := 0; i < val.NumField(); i++ {
				field := val.Field(i)
				fieldName := typ.Field(i).Name

				switch field.Kind() {
				case reflect.String:
					if field.String() == "" {
						t.Errorf("%s.%s is empty", d.name, fieldName)
					}
				case reflect.Func:
					if field.IsNil() {
						t.Errorf("%s.%s func is nil", d.name, fieldName)
					}
				default:
					t.Errorf("%s.%s has unexpected kind %v", d.name, fieldName, field.Kind())
				}
			}
		})
	}
}

func TestGetMessagesFallback(t *testing.T) {
	t.Parallel()

	if getMessages("en") != messagesEN {
		t.Error("getMessages(en) != messagesEN")
	}
	if getMessages("zh") != messagesZH {
		t.Error("getMessages(zh) != messagesZH")
	}
	if getMessages("") != messagesZH {
		t.Error("getMessages(\"\") != messagesZH (fallback)")
	}
	if getMessages("unknown") != messagesZH {
		t.Error("getMessages(unknown) != messagesZH (fallback)")
	}
}

func TestMessagesFuncs(t *testing.T) {
	t.Parallel()

	for _, msg := range []*Messages{messagesZH, messagesEN} {
		if got := msg.PastedRunesCount(5); got == "" {
			t.Error("PastedRunesCount(5) returned empty")
		}
		if got := msg.LocalControlErrorNotice("target_saved", ipc.ErrLocked); got == "" {
			t.Error("LocalControlErrorNotice(target_saved, ErrLocked) returned empty")
		}
		if got := msg.LocalControlErrorNotice("target_tested", context.DeadlineExceeded); got == "" {
			t.Error("LocalControlErrorNotice returned empty for DeadlineExceeded")
		}
		if got := msg.LocalControlErrorNotice("unknown", errors.New("custom")); got == "" {
			t.Error("LocalControlErrorNotice returned empty for custom error")
		}
	}
}
