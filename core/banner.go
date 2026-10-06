package core

import "fmt"

const green = "\033[32m"
const reset = "\033[0m"

const banner = `
   ██████╗ ██████╗ ██╗███╗   ██╗
  ██╔═══██╗██╔══██╗██║████╗  ██║
  ██║   ██║██║  ██║██║████╗  ██║
  ██║   ██║██║  ██║██║██║╚██╗██║
   ██████╔╝██████╔╝██║██║ ╚████║
   ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

            ᛟᛁᚾ
   ─────────────────────
     RECONNAISSANCE
     ATTACK SURFACE
     INTELLIGENCE

        [ ODIN SEES ALL ]
`

func PrintBanner() {
	fmt.Printf("%s%s%s", green, banner, reset)
}
