package slice

// ContainsString checks if the slice has the contains a value.
func ContainsString(slice []string, contains string) bool {
	for _, v := range slice {
		if v == contains {
			return true
		}
	}
	return false
}
