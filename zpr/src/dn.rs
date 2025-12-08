// Well-known DNs.

const DN_CN_DER_PREFIX_LEN: usize = 13;

const fn encode_dn_cn_as_der<const DER_LEN: usize>(cn: &str) -> [u8; DER_LEN] {
    let mut der = [0u8; DER_LEN];

    der[0] = 0x30; // SEQUENCE
    der[1] = (cn.len() + 11) as u8; // length

    der[2] = 0x31; // SET
    der[3] = (cn.len() + 9) as u8; // length

    der[4] = 0x30; // SEQUENCE
    der[5] = (cn.len() + 7) as u8; // length

    der[6] = 0x06; // OBJECT IDENTIFIER
    der[7] = 3; // length = 3
    der[8] = 2 * 40 + 5; // 2.5
    der[9] = 4; // .4
    der[10] = 3; // .3 -> commonName

    der[11] = 0x0C; // UTF8STRING
    der[12] = cn.len() as u8; // length

    let mut i = 0;
    while i < cn.len() {
        der[13 + i] = cn.as_bytes()[i];
        i += 1;
    }

    der
}

macro_rules! dn_cn_der {
    ($cn:expr) => {
        encode_dn_cn_as_der::<{ DN_CN_DER_PREFIX_LEN + $cn.len() }>($cn)
    };
}

pub const VISA_SERVICE_CN: &str = "vs.zpr";
pub const VISA_SERVICE_DN: &[u8] = &dn_cn_der!(VISA_SERVICE_CN);
