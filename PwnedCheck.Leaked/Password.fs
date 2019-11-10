namespace PwnedCheck.Leaked

module Password =

    open CryptographyExtensions
    
    
    type HashedPwd =
        | Sha1 of pwd: string
    
    type Password =
        | Clear of pwd: string
        | Hashed of HashedPwd


    let sha1Pwd = encodeWithSha1 >> Sha1

    let hashPwd (clearTextPwd: string): Password =
        clearTextPwd
        |> sha1Pwd
        |> Hashed
