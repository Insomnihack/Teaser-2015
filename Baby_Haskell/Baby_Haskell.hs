import System.Environment
import Data.Char

insocrypt :: String -> String
insocrypt [] = []
insocrypt [x]
    | x == 'A' = ['_']
    | x == 'b' = ['}']
    | x == 'c' = ['{']
    | x == 'd' = ['m']
    | x == 'E' = ['N']
    | x == 'f' = ['b']
    | x == 'g' = ['v']
    | x == 'H' = ['c']
    | x == 'I' = ['x']
    | x == 'j' = ['w']
    | x == 'K' = ['L']
    | x == 'L' = ['K']
    | x == 'm' = ['j']
    | x == 'N' = ['H']
    | x == 'o' = ['g']
    | x == 'p' = ['f']
    | x == 'q' = ['d']
    | x == 'r' = ['S']
    | x == 'S' = ['q']
    | x == 't' = ['p']
    | x == 'u' = ['o']
    | x == 'v' = ['I']
    | x == 'w' = ['u']
    | x == 'x' = ['y']
    | x == 'y' = ['t']
    | x == 'z' = ['r']
    | x == '{' = ['E']
    | x == '}' = ['z']
    | x == '_' = ['A']
    | True = [x]
insocrypt (x:xs) = insocrypt [x] ++ insocrypt xs

main :: IO ()
main = do
    args <- getArgs
    if length args /= 1
        then
            putStrLn "Usage: ./task <flag>"
        else if insocrypt (args !! 0) == "xHqEYgoA5h0olmA1eaSnAc_qLNKKz"
            then putStrLn "Congratz"
            else
                putStrLn $ "Nope"
