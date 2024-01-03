package main

import (
	"fmt"
)

type Field struct {
	p int
}

type EllipticCurve struct {
	a, b  int
	field Field
}

type Point struct {
	x, y int
}

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

func (p Point) Add(line EllipticCurve, q Point) Point {
	// Если точки совпадают, то возвращаем точку бесконечности
	if p.x == q.x && p.y == q.y {
		return Point{x: -1, y: -1}
	}

	// Если одна из точек равна точке бесконечности, то возвращаем другую точку
	if p.x == -1 && p.y == -1 {
		return q
	}
	if q.x == -1 && q.y == -1 {
		return p
	}

	dy := q.y - p.y
	dx := q.x - p.x

	if dx < 0 {
		dx = dx + line.field.p
	}
	if dy < 0 {
		dy = dy + line.field.p
	}

	m := (dy * reversedNumber(dx, line.field.p)) % line.field.p
	if m < 0 {
		m += line.field.p
	}
	x := (m*m - p.x - q.x) % line.field.p
	y := (m*(p.x-x) - p.y) % line.field.p

	if x < 0 {
		x += line.field.p
	}

	if y < 0 {
		p.y += line.field.p
	}

	return Point{x, y}
}

func main() {
	// Задаем коэффициенты кривой
	c := EllipticCurve{a: 1, b: 1, field: Field{p: 5}}

	// Задаем точку, принадлежащую кривой
	p := Point{x: 4, y: 2}

	// Вычисляем следующую точку
	q := p.Add(c, Point{x: 3, y: 1})

	// Выводим результат
	fmt.Println(q)
}
