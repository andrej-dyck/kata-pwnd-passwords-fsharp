namespace PwnedCheck.Leaked

module CryptographyExtensions =

    open System.Security.Cryptography
    open System.Text
    open StringExtensions
    

    let encodeWithSha1 (text: string): string =
        text
        |> Encoding.UTF8.GetBytes
        |> SHA1.Create().ComputeHash
        |> Array.map (sprintf "%x")
        |> String.concat ""
        |> toUpper
