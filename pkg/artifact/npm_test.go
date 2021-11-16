package artifact

import (
	"reflect"
	"testing"
)

func TestGetDependenciesFromPackageLock(t *testing.T) {
	type args struct {
		packageLockPath string
	}
	tests := []struct {
		name    string
		args    args
		want    []*Artifact
		wantErr bool
	}{
		{name: "v2or3 package lock file", args: args{packageLockPath: "../../testfiles/package-lock.json"},
			want: []*Artifact{
				{Name: "has", Version: "1.0.3", Location: "https://registry.npmjs.org/has/-/has-1.0.3.tgz", SHA256: "sha512-f2dvO0VU6Oej7RkWJGrehjbzMAjFp5/VKPp5tTpWIV4JHHZK1/BxbFRtf/siA2SWTe09caDmVtYYzWEIbBS4zw=="},
				{Name: "function-bind", Version: "1.1.1", Location: "https://registry.npmjs.org/function-bind/-/function-bind-1.1.1.tgz", SHA256: "sha512-yIovAzMX49sF8Yl58fSCWJ5svSLuaibPxXQJFLmBObTuCr0Mf1KiPopGM9NiFjiYBCbfaa2Fh6breQ6ANVTI0A=="},
			}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDependenciesFromPackageLock(tt.args.packageLockPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDependenciesFromPackageLock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(&got, &tt.want) {
				t.Errorf("GetDependenciesFromPackageLock() = %v, want %v", got, tt.want)
			}
		})
	}
}
