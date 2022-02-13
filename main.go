package main

import (
	"fmt"
	"log"
	"strconv"
)

func main() {
	// "6G2D2D5D4B2D2D8W2D3F6G2D2D7J2D3F2D2D3F2D8W2D2D1Z3F8W4C" Hasil enkripsi
	// Proses mengubah hasil enkripsi ke plaintext
	fmt.Println(toDecrypt("6G2D2D5D4B2D2D8W2D3F6G2D2D7J2D3F2D2D3F2D8W2D2D1Z3F8W4C"))
}

// merubah array code blok jadi deskripsi
func toDecrypt(password string) (result string) {
	// urutan kode deskripsinya
	var alphabet string = "[]abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// merubah dari kode blok ke plaintex sebenarnya.
	for _, v := range dePrima(password) {
		rangevalue, _ := strconv.Atoi(v)
		result += alphabet[rangevalue : rangevalue+1]
	}
	return result
}

// Fungsi untuk scan dari enkripsi ke code blok yang akan jadi index alphabet
func dePrima(plaintext string) (returnvl []string) {
	key := [72]string{"1Z", "2D", "3F", "4C", "4B", "5D", "6G", "7J", "8L", "8W", "9W", "1Q", "4H", "5K", "3D", "2F", "1D", "1B", "1A", "2G", "3M", "4D", "6D", "6H", "7F", "7D", "12", "55", "34", "77", "65", "88", "87", "85", "90", "09", "07", "21", "23", "28", "29", "20", "39", "80", "84", "78", "B1", "D1", "C1", "F1", "G1", "R1", "U1", "A1", "B2", "C2", "D2", "E2", "F2", "G2", "B3", "C3", "D3", "F3", "G3", "B4", "C4", "D4", "F4", "G4", "B5", "C5"}
	var chiperText string
	// variable kosong untuk menampung hasil scaning dari enkripsi ke code blok
	result := []string{}
	// mengetahui panjang enkripsi
	n := len(plaintext)
	var prima int = 173 // nilai prima sebagai kunci
	// modulasi panjang enkripsi dengan bilangan genap
	if n%2 == 0 {
		// dibagi 2, untuk range perulangan, karena akan diambil setiap 2 huruf dari enkripsi
		n = n / 2
		// Melakukan perulangan untuk mendapatkan nilai urut key dari enkripsinya.
		for a := 0; a < n; a++ {
			aa := a * 2
			aaa := a*2 + 2
			for k, v := range key {
				// jika 2 huruf enkripsi ada di variable key, maka simpan no urutnya ke chiper.
				if v == plaintext[aa:aaa] {
					chiperText += strconv.Itoa(k)
				} else {
					continue
				}
			}
		}
	} else {
		msgDePrima := "Incorrect encryption!"
		log.Println(msgDePrima)
		returnvl = append(returnvl, "ERROR")
		return returnvl
	}
	var preDecrypt string
	if len(chiperText) > 19 {
		sliceChiperRight := chiperText[len(chiperText)-7:]
		sliceChiperLeft := chiperText[:len(chiperText)-7]
		x, _ := strconv.Atoi(sliceChiperRight)
		preDecrypt = sliceChiperLeft + fmt.Sprint(x-prima)

	} else {
		// Convert string to int
		chiperTextInt, _ := strconv.Atoi(chiperText)
		// dikurangi bilangan prima, lalu diconvert lagi ke string
		var chipertoText int = chiperTextInt - prima
		// int conver to string, dengan memanfaatkan Sprint
		preDecrypt = fmt.Sprint(chipertoText)
	}
	seq := 0
	status := true
	for status {
		// defer ini akan selalu dijalankan diakhir, meskipun error
		defer func() {
			// menangkap error saat program berjalan
			if err := recover(); err != nil {
				// log.Println("panic occurred:", err)
				// log.Println("Decrypted!")
				returnvl = result
			}
		}()
		if preDecrypt[seq:seq+1] == "1" {
			// Jika angkanya 1, maka baca 2 angka selanjutnya.
			result = append(result, preDecrypt[seq+1:seq+2]+preDecrypt[seq+2:seq+3])
			seq += 3
		} else {
			// Jika bukan, maka hanya baca 1 angka itu saja.
			result = append(result, preDecrypt[seq:seq+1])
			seq += 1
		}
	}
	return returnvl
}
