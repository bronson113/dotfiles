#!/usr/bin/sage
from Crypto.Util.number import long_to_bytes, bytes_to_long
from subprocess import check_output
from re import findall

#from pwn import *
#nc_str = "<++>"
#_, host, port = nc_str.split(" ")
#p = remote(host, int(port))

# def flatter(M):
#     # compile https://github.com/keeganryan/flatter and put it in $PATH
#     z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
#     ret = check_output(["flatter"], input=z.encode())
#     return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

# LLL (5*5 with weights)
#weights = [1, 1, 1, 1/2^512, 1/2^504]
#Q = diagonal_matrix(weights)
#L = Matrix([
#    [hm, hm, 1, 0, 0],
#    [s1, s2, 0, 1, 0],
#    [r1, r2, 0, 0, 1],
#    [q1, 0, 0, 0, 0],
#    [0, q2, 0, 0, 0]])
#L = L*Q
#Sol = flatter(L)/Q
#print(Sol) 



