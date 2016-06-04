import d3des_vnc as d # for brevity - narrow column

def get_vnc_enc(password):
    passpadd = (password + '\x00'*8)[:8]
    strkey = ''.join([ chr(x) for x in d.vnckey ])
    ekey = d.deskey(strkey, False)

    ctext = d.desfunc(passpadd, ekey)
    return ctext.encode('hex')
    
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        print get_vnc_enc(sys.argv[1])
    else:
        print 'usage: %s <password>' % sys.argv[0]