var = {chr(i): 0 for i in range(ord("A"), ord("Z") + 1)}
s = "NTCGPDOPANFLHJINTOOFITOVJHJCTMMHIHEMTCPFDWTSOFSHTOGFWTETTJJTBTOOFSZOVEOCHCVCHPJHOCGTOHNOMTOCNTCGPDCGFCSTOMFBTOFBGFSFBCTSHJCGTQMFHJCTYCXHCGFAHYTDDHAATSTJCBGFSFBCTSHJCGTBHOGTSCTYCCGHONTCGPDOSTOTSWTOCGTMTCCTSASTRVTJBZHJCGTOMFHJCTYCFJDOPPJTBFJOTFSBGAPSCGTOMFHJCTYCASPNFIHWTJBHOGTSCTYCEZBPNQFSHJICGTASTRVTJBZPATFBGMTCCTSFIFHJOCCGTLJPXJBPNNPJASTRVTJBZHJCGTVJDTSMZHJIMFJIVFIT"
for i in range(len(s)):
    var[s[i]] += 1
for i in var:
    var[i] /= len(s)
ls = sorted(var.items(), key=lambda item: item[1], reverse=True)
posibility = "etaoinshrdlcumwfgypbvkjxqz"
ls = [i[0] for i in ls]
verb = {ls[i]: posibility[i] for i in range(len(ls))}
res = [verb[i] for i in s]
res = "".join(res)


m = "methodsofmakingmessagesunintelligibletoadversarieshavebeennecessarysubstitutionisthesimplestmethodthatreplacesacharacterintheplaintextwithafixeddifferentcharacterintheciphertextthismethodpreservestheletterfrequencyintheplaintextandsoonecansearchfortheplaintextfromagivenciphertextbycomparingthefrequencyofeachletteragainsttheknowncommonfrequencyintheunderlyinglanguage"


key = {m[i]: s[i] for i in range(len(s))}