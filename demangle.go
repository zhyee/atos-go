package atos

import (
	"os/exec"
	"strings"
	"sync"

	"github.com/ianlancetaylor/demangle"
)

type cachedDemangleResult struct {
	name string
	ok   bool
}

var (
	demangleCache sync.Map

	swiftDemanglerOnce sync.Once
	swiftDemanglerPath string
	swiftDemanglerArgs []string
)

func displayFunctionName(linkageName, fallbackName string) string {
	if linkageName != "" {
		if name, ok := demangleFunctionName(linkageName); ok {
			return name
		}
	}
	if fallbackName != "" {
		return fallbackName
	}
	return linkageName
}

func demangleFunctionName(name string) (string, bool) {
	if cached, ok := demangleCache.Load(name); ok {
		result := cached.(cachedDemangleResult)
		return result.name, result.ok
	}

	var result cachedDemangleResult
	switch {
	case isSwiftMangledName(name):
		result.name, result.ok = demangleSwiftName(name)
	case strings.HasPrefix(name, "_Z"), strings.HasPrefix(name, "_R"):
		var err error
		result.name, err = demangle.ToString(name, demangle.LLVMStyle)
		result.ok = err == nil
	}
	if result.ok && (result.name == "" || result.name == name) {
		result = cachedDemangleResult{}
	}

	actual, _ := demangleCache.LoadOrStore(name, result)
	result = actual.(cachedDemangleResult)
	return result.name, result.ok
}

func isSwiftMangledName(name string) bool {
	return strings.HasPrefix(name, "$s") ||
		strings.HasPrefix(name, "$S") ||
		strings.HasPrefix(name, "_T")
}

func demangleSwiftName(name string) (string, bool) {
	path, prefixArgs := swiftDemangler()
	if path == "" {
		return "", false
	}
	args := append(append([]string{}, prefixArgs...), "--compact", "--simplified", name)
	output, err := exec.Command(path, args...).Output()
	if err != nil {
		return "", false
	}
	demangled := strings.TrimSpace(string(output))
	if demangled == "" || strings.ContainsRune(demangled, '\n') {
		return "", false
	}
	return demangled, true
}

func swiftDemangler() (string, []string) {
	swiftDemanglerOnce.Do(func() {
		if path, err := exec.LookPath("swift-demangle"); err == nil {
			swiftDemanglerPath = path
			return
		}
		if path, err := exec.LookPath("xcrun"); err == nil {
			swiftDemanglerPath = path
			swiftDemanglerArgs = []string{"swift-demangle"}
		}
	})
	return swiftDemanglerPath, swiftDemanglerArgs
}
