package slice

import "testing"

func TestContainsString(t *testing.T) {
	type args struct {
		slice    []string
		contains string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "should contain value",
			args: args{slice: []string{"ab", "cd"}, contains: "cd"},
			want: true,
		},
		{
			name: "should not contain value",
			args: args{slice: []string{"ab", "cd"}, contains: "ef"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsString(tt.args.slice, tt.args.contains); got != tt.want {
				t.Errorf("ContainsString() = %v, want %v", got, tt.want)
			}
		})
	}
}
