namespace PwnedCheck

module Main =

    open System
    open FSharp.Data
    open PwnedCheck.Leaked.Password
    open PwnedCheck.Leaked.LeakageCheck
    open PwnedCheck.Leaked.PwnedPasswords


    let private pwnedCheck =
        Clear >> isPwnedPassword (pwnedPasswords Http.RequestString)

    let private analyzePassword =
        pwnedCheck
        >> function
            | LeakedPassword times -> sprintf "This password has already been leaked %d times!" times
            | UnleakedPassword -> sprintf "This password seems good enough; no leaks yet."


    [<EntryPoint>]
    let main _ =
        printfn "Is My Password Save?"
        printfn " https://haveibeenpwned.com/"
        printfn " a secure check via k-anonymity (your password never leaves your pc)"

        while true do
            printfn "\nEnter the password you'd like to check:"

            Console.ReadLine()
            |> analyzePassword
            |> printfn "%s"

        0 // exit code
