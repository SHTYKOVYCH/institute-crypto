package main

import (
	"des/des"
	"fmt"
)

func main() {
	key := "0E329232EA6D0D73"

	fmt.Println(des.EncryptMessage("Your lips are smoother than vaseline\r\n", key))
	fmt.Println(des.DecryptMessage("c0999fdde378d7ed727da00bca5a84ee47f269a4d6438190d9d52f78f5358499828ac9b453e0e653", key))
}
