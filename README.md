# Simple Antivirus

## Author
**Methodios Zacharioudakis**

---

### Overview
This project simulates a **simple antivirus** with the options  
to **scan**, **inspect**, **monitor**, **slice (lock)** and **unlock**  
a specified folder.  
It was conducted as an assignment for my undergraduate studies. 

---

**YARA-rule**
```sh
rule KozaliBear_attack
{
	strings:
		$md = {85 57 8c d4 40 4c 6d 58 6c d0 ae 1b 36 c9 8a ca}
		$sha = {d5 6d 67 f2 c4 34 11 d9 66 52 5b 32 50 bf aa 1a 85 db 34 bf 37 14 68 df 1b 6a 98 82 fe e7 88 49}
		$wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
		$sign = {98 1d 00 00 ec 33 ff ff fb 06 00 00 00 46 0e 10}
	condition:
		$md or $sha or $wallet or $sign
}
```

**To compile:**
```sh
make all
```

**To clean compilation products**
```sh
make clean
```

---

### Requirements