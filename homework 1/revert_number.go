package main

import "fmt"

func mod(a int, module int) int {
	res := 0

	for (res-a)%module != 0 {
		res += 1
	}

	return res
}

func extGCD(a int, b int) (int, int, int) {
	if a == 0 {
		return b, 0, 1
	}

	d, x1, y1 := extGCD(b%a, a)
	x := y1 - (b/a)*x1
	y := x1

	return d, x, y
}

func reversedNumber(num int, module int) int {
	d, a, _ := extGCD(num, module)

	if d != 1 {
		return module
	}

	return mod(a, module)
}

func chinesseTeory(a []int, m []int) int {
	M := func() int {
		t := 1
		for _, i := range m {
			t *= i
		}

		return t
	}()

	Mi := make([]int, len(m))
	Yi := make([]int, len(m))

	for i := range m {
		Mi[i] = M / m[i]
		Yi[i] = reversedNumber(Mi[i], m[i])
	}

	x := 0

	for i := range m {
		x += a[i] * Mi[i] * Yi[i]
	}

	return mod(x, M)
}

func main() {
	fmt.Println(reversedNumber(2, 5))
	fmt.Println(chinesseTeory([]int{5, 3, 10}, []int{7, 11, 13}))
}
