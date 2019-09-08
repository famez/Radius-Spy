package utils

func Contains(container []int, value int) bool {

	for _, val := range container {
		if val == value {
			return true
		}
	}

	return false

}

func Min(a int, b int) int {

	if a < b {
		return a
	}

	return b
}

func CopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = CopyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}

func BigEndian3BytesToUint32(b []byte) uint32 {

	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}
