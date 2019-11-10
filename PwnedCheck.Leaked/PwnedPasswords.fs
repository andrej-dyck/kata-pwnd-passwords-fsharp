namespace PwnedCheck.Leaked

module PwnedPasswords =

    open System
    open StringExtensions
    open Password
    open LeakageCheck


    type HttpGet = string -> string


    let private toRecord (sha1Prefix: string) (sha1PostfixAndFrequency: string) =
        let toRecord sha1Postfix frequency =
            let fullSha1 = Sha1 <| sha1Prefix + sha1Postfix
            let frequency = Int32.Parse frequency

            { Password = fullSha1; Frequency = frequency }

        let mapItems toRecord items =
            match items with
            | sha1Posfix :: frequency :: _ -> toRecord sha1Posfix frequency
            | _ -> failwithf "unexpected format of response %s" sha1PostfixAndFrequency

        sha1PostfixAndFrequency
        |> split [| ':' |]
        |> mapItems toRecord

    let private toRecords sha1Prefix httpResponse =
        httpResponse
        |> toTrimmedLines
        |> List.map (toRecord sha1Prefix)

    let private toSha1Prefix encodedPwd =
        let toSha1String pwd =
            match pwd with
            | Sha1 s -> s.[..4]

        let take5 (s: string) =
            if s.Length >= 5
            then s.[..4]
            else failwithf "unexpected encoded password %s" s

        encodedPwd
        |> toSha1String
        |> take5


    let pwnedPasswords (httpGet: HttpGet) (hashedPwd: HashedPwd): PwnedPassword list =
        let sha1Prefix = toSha1Prefix hashedPwd

        sha1Prefix
        |> (+) "https://api.pwnedpasswords.com/range/"
        |> httpGet
        |> toRecords sha1Prefix
