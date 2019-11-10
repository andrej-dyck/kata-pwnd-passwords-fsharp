namespace PwnedCheck.Leaked.Test

open Xunit
open FsUnit.Xunit

open FSharp.Data

open PwnedCheck.Leaked.Password
open PwnedCheck.Leaked.LeakageCheck
open PwnedCheck.Leaked.PwnedPasswords

module PwnedPasswordsIntegrationTest =

    let private httpGet = Http.RequestString


    [<Fact>]
    let ``API of pwnedpasswords.com works``() =
        let response = httpGet "https://api.pwnedpasswords.com/range/21BD1"

        response |> should startWith "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                                      00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                                      011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n\
                                      012A7CA357541F0AC487871FEEC1891C49C:2"

    [<Fact>]
    let ``API abstraction returns list of records``() =
        let records = pwnedPasswords httpGet (Sha1 "21BD1")

        records |> should contain
            { Password = Sha1 "21BD10018A45C4D1DEF81644B54AB7F969B88D65"; Frequency = 1 },
            { Password = Sha1 "21BD100D4F6E8FA6EECAD2A3AA415EEC418D38EC"; Frequency = 2 },
            { Password = Sha1 "21BD1011053FD0102E94D6AE2F8B83D76FAF94F6"; Frequency = 1 },
            { Password = Sha1 "21BD1012A7CA357541F0AC487871FEEC1891C49C"; Frequency = 2 }


module LeackageCheckIntegrationTest =

    let private httpGet = Http.RequestString


    [<Fact>]
    let ``PwnedCheck indicates the passwords leakage for known password``() =
        let checkResult =
            Hashed(Sha1 "21BD10018A45C4D1DEF81644B54AB7F969B88D65")
            |> isPwnedPassword (pwnedPasswords httpGet)

        checkResult |> should equal (LeakedPassword 1)
