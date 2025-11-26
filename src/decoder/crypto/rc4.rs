//! RC4 流密码实现

pub struct Rc4 {
    state: Vec<u8>,
    state_len: usize,
    i: usize,
    j: usize,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let key_len = key.len();
        let mut state = vec![0u8; key_len];
        
        for i in 0..key_len {
            state[i] = i as u8;
        }

        let mut j: usize = 0;
        for i in 0..key_len {
            j = (j + state[i] as usize + key[i] as usize) % key_len;
            state.swap(i, j);
        }

        Rc4 {
            state,
            state_len: key_len,
            i: 0,
            j: 0,
        }
    }

    /// 生成密钥流并与 buffer 异或
    #[allow(dead_code)]
    pub fn derive(&mut self, buffer: &mut [u8]) {
        let n = self.state_len;
        
        for byte in buffer.iter_mut() {
            self.i = (self.i + 1) % n;
            self.j = (self.j + self.state[self.i] as usize) % n;
            self.state.swap(self.i, self.j);
            
            let final_idx = (self.state[self.i] as usize + self.state[self.j] as usize) % n;
            *byte ^= self.state[final_idx];
        }
    }

    /// 生成密钥流到指定 buffer
    pub fn generate_stream(&mut self, buffer: &mut [u8]) {
        let n = self.state_len;
        
        for byte in buffer.iter_mut() {
            self.i = (self.i + 1) % n;
            self.j = (self.j + self.state[self.i] as usize) % n;
            self.state.swap(self.i, self.j);
            
            let final_idx = (self.state[self.i] as usize + self.state[self.j] as usize) % n;
            *byte = self.state[final_idx];
        }
    }
}
