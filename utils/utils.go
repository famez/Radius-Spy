package utils

func Contains(container []int, value int) bool {

	for _, val := range container {
		if val == value {
			return true
		}
	}

	return false

}
