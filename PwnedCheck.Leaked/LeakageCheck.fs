namespace PwnedCheck.Leaked

module LeakageCheck =

    open System
    open Password


    type PwnedPassword =
        { Password: HashedPwd; Frequency: int }

    type LeakResult =
        | LeakedPassword of times: int
        | UnleakedPassword


    let private toPwnedCheck pwnedPassword =
        match pwnedPassword with
        | Some r -> LeakedPassword r.Frequency
        | None -> UnleakedPassword

    let private check pwnedPasswords hashedPwd =
        let equalHash hashedPwd =
            fun pwnedPassword -> String.Equals(pwnedPassword.Password, hashedPwd)

        pwnedPasswords hashedPwd
        |> List.tryFind (equalHash hashedPwd)
        |> toPwnedCheck


    let isPwnedPassword (pwnedPasswords: HashedPwd -> PwnedPassword list) (password: Password): LeakResult =
        check pwnedPasswords
        <| match password with
           | Clear pwd -> (sha1Pwd pwd)
           | Hashed pwd -> pwd
