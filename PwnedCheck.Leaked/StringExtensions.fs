namespace PwnedCheck.Leaked

module StringExtensions =

    open System

    let split (chars: char []) (s: string) =
        s.Split chars |> Array.toList

    let trim (s: string) =
        s.Trim()

    let isNotNullNorWhitespace =
        String.IsNullOrWhiteSpace >> not

    let toLines =
        split [| '\r'; '\n' |]

    let toTrimmedLines =
        toLines
        >> List.map trim
        >> List.filter isNotNullNorWhitespace

    let toUpper (s: string) =
       s.ToUpperInvariant()
