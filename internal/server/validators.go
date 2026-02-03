package server

import (
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func isUUIDv4(value string) bool {
	engine := binding.Validator.Engine()
	validate, ok := engine.(*validator.Validate)
	if !ok || validate == nil {
		return false
	}
	return validate.Var(value, "required,uuid4") == nil
}
