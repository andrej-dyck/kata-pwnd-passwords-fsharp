namespace PwnedCheck.Leaked.Test

open Xunit
open FsUnit.Xunit

open PwnedCheck.Leaked.Password
open PwnedCheck.Leaked.LeakageCheck

module CheckPasswordLeakageTest =

    let private fakePwnedPasswords fakeResponse =
        fun _ -> fakeResponse

    [<Fact>]
    let ``unleaked password when pwned passwords are empty``() =
        let checkResult =
            fakePwnedPasswords []
            |> isPwnedPassword
            <| Clear "password1"

        checkResult |> should equal UnleakedPassword

    [<Fact>]
    let ``unleaked password when pwned passwords does not contain the hashed version of the password``() =
        let checkResult =
            fakePwnedPasswords [
                { Password = Sha1 "E38AD00969D6155DDF8FDEA98D8E0F85ADE21568"; Frequency = 2 }
                { Password = Sha1 "E38AD00B550FB04203E48A4777327812F00DB096"; Frequency = 9 }
            ]
            |> isPwnedPassword
            <| Clear "password1"

        checkResult |> should equal UnleakedPassword

    [<Fact>]
    let ``leaked password when pwned passwords contains the hashed version of the password``() =
        let checkResult =
            fakePwnedPasswords [
                { Password = Sha1 "E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D"; Frequency = 2401761 }
            ]
            |> isPwnedPassword
            <| Clear "password1"

        checkResult |> should equal (LeakedPassword 2401761)


module HashPwdTest =

    [<Fact>]
    let ``hashes clear text with sha1``() =
        hashPwd "password1" |> should equal
                            <| Hashed(Sha1 "E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D")
