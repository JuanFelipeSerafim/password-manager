"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
         //jaja comento cada um
         saltChavePrincipal: null, 
         saltHMAC: null, 
         saltAES: null,
         assinaturaChavePrincipal:null, 
         saltsKVS: {}, 
         kvsDeFato: {} 
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
         chavePrivadaHMAC: null,
         chavePrivadaAES: null,
         hashKVS: null
    };

  };

  //funcao auxiliar
  static async keyDerivation(password){
    let saltChavePrincipal = getRandomBytes(16);
    let saltHMAC = getRandomBytes(16);
    let saltAES = getRandomBytes(16);
    
    let rawKey = await subtle.importKey("raw", stringToBuffer(password),"PBKDF2", false, ["deriveKey"]); //gerada a partir da senha do usuário para ser derivada em outras subchaves
    
    const chavePrincipal = await subtle.deriveKey( //gerada a partir da senha do usuário
      {
        "name": "PBKDF2",
        salt: saltChavePrincipal,
        "iterations": PBKDF2_ITERATIONS,
        "hash": "SHA-256"
      },
      rawKey,
      { "name": "HMAC", "hash": "SHA-256", "length": 256},
      false, 
     ["sign", "verify"] 
    );

    const rawHMAC = await subtle.sign("HMAC", chavePrincipal, saltHMAC); // chave aleatoria "bruta" (considerando o salt) pro HMAC
    const rawAES = await subtle.sign("HMAC", chavePrincipal, saltAES); // chave aleatoria "bruta" (considerando o salt) pro AES-GCM

    
    const chaveHMAC = await subtle.importKey( // objeto retornado para ser utilizado em outras funcoes da biblioteca. Pro hmac eu posso assinar e verificar
      "raw",
      rawHMAC,
      { name:"HMAC", hash: "SHA-256"}, 
      false,
      ["sign", "verify"] 
    );

    const chaveAES = await subtle.importKey( // objeto retornado para ser utilizado em outras funcoes da biblioteca. Pro hmac eu posso encriptar e decriptar
      "raw",
      rawAES,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"] 
    );
    
    return { // retorna tudo num JSON pra ser utilizada pela init()
      saltChavePrincipal:encodeBuffer(saltChavePrincipal),
      saltHMAC: encodeBuffer(saltHMAC),
      saltAES: encodeBuffer(saltAES),
      rawKey: rawKey,
      chavePrincipal: chavePrincipal,
      rawAES: encodeBuffer(rawAES),
      rawHMAC: encodeBuffer(rawHMAC),
      chaveHMAC: chaveHMAC,
      chaveAES: chaveAES
    }
  }
  
  
  
  
  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const chavesESalts = await Keychain.keyDerivation(password)

    const kchain = new Keychain();

    kchain.secrets.chavePrivadaHMAC = chavesESalts.chaveHMAC;
    kchain.secrets.chavePrivadaAES = chavesESalts.chaveAES;
    kchain.secrets.hashKVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(kchain.data.kvsDeFato) )))); // se liga no encodeBuffer aqui pra serializar o dado do stringify em um tipo certo!!
    kchain.data.assinaturaChavePrincipal=bufferToString(await subtle.sign("HMAC", chavesESalts.chavePrincipal, stringToBuffer("assinado por jfss"))); //garantia da integridade da senha advinda da funcao auxiliar acima
       
    kchain.data.saltChavePrincipal = chavesESalts.saltChavePrincipal; //sao strings agora. 
    kchain.data.saltHMAC = chavesESalts.saltHMAC; //sao strings agora
    kchain.data.saltAES = chavesESalts.saltAES; //sao strings agora

    return kchain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if (trustedDataCheck !== null) {
      if (trustedDataCheck !== bufferToString(await subtle.digest("SHA-256", decodeBuffer(repr)))) { //esse repr tá em base64!!
        throw "KVS adulterado";
      }
    }
       
      let password_manager = JSON.parse(decodeBuffer(repr)); ///vai ta o this.data nesse cara aqui

      //tudo igual ao keyDerivation() praticamente
      //É necessário realizar isso para verificar se de fato o KVS armazenado é aberto pela senha do usuário
      let rawKey = await subtle.importKey("raw", stringToBuffer(password),"PBKDF2", false, ["deriveKey"]);
    
      const chavePrincipal = await subtle.deriveKey(
        {
          "name": "PBKDF2",
          salt: decodeBuffer(password_manager.saltChavePrincipal),
          "iterations": PBKDF2_ITERATIONS,
          "hash": "SHA-256"
        },
        rawKey,
        { "name": "HMAC", "hash": "SHA-256", "length": 256}, 
        false, 
      ["sign", "verify"] 
      );

      const rawHMAC = await subtle.sign("HMAC", chavePrincipal, decodeBuffer(password_manager.saltHMAC));
      const rawAES = await subtle.sign("HMAC", chavePrincipal, decodeBuffer(password_manager.saltAES));

    
      const chaveHMAC = await subtle.importKey(
        "raw",
        rawHMAC,
        { name:"HMAC", hash: "SHA-256"}, 
        false,
        ["sign", "verify"]
      );

      const chaveAES = await subtle.importKey(
        "raw",
        rawAES,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"] 
      );
      // verificacao de senha de usuário é possível de ser utilizada para resgatar as informacoes do KVS
      const testeCoerenciaChavePrincipal = await subtle.verify("HMAC", chavePrincipal, stringToBuffer(password_manager.assinaturaChavePrincipal), stringToBuffer("assinado por jfss")); 
      
      //se a senha for incorreta...
      if (!testeCoerenciaChavePrincipal) throw "Senha do gerenciador invalida";

      //nova instancia pra copiar os dados do arquivo
      let kchain = new Keychain();

      kchain.data = password_manager;

      kchain.secrets.chavePrivadaHMAC = chaveHMAC;
      kchain.secrets.chavePrivadaHMAC = chaveAES;
      kchain.secrets.hashKVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(kchain.data.kvsDeFato)))));

      return kchain;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    let dump_data = this.data;

    const serialized = encodeBuffer(JSON.stringify(dump_data)); // ja codificada em base64. É indicacao do projeto
    const checksum = bufferToString(await subtle.digest("SHA-256", decodeBuffer(serialized))); // sem estar em base64. é o sha256 "puro". no entanto, a biblioteca só usa parametros Buffer ou similares, por isso o decode...
    return [serialized, checksum];
  };



  static retiraPreenchimento(valor) {
    var i = valor.length;
    while (i && valor[i-1]=="\0")
      --i;
    return valor.substr(0,i-1);
}

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const sha256KVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(this.data.kvsDeFato)))));
    if(sha256KVS !== this.secrets.hashKVS) throw "rollback attack!!!" // verificacao inicial do rollback attack

    const linkHMAC = bufferToString(await subtle.sign("HMAC", this.secrets.chavePrivadaHMAC, stringToBuffer(name)));

    //se o link nao existir no KVS...
    if (!(linkHMAC in this.data.kvsDeFato)) return null; 
  
    //pega a senha encriptada e decripta
    const senhaEmAES = decodeBuffer(this.data.kvsDeFato[linkHMAC]); 
    const senha_pura = await subtle.decrypt({name: "AES-GCM", iv: this.data.saltsKVS[linkHMAC]}, this.secrets.chavePrivadaAES, senhaEmAES);

    return Keychain.retiraPreenchimento(bufferToString(senha_pura));// retira o preenchimento utilizado para deixar 64 caracteres na senha
  };

  
  //funcao auxiliar
  static preencheString (valor, n, pad){
    var t = valor;
    if (n > valor.length){
        for (var i = 0; i < n-valor.length; i++){
            if (i === 0){t+="1"; // de acordo com a RFC1321, secao secundaria 3.1 -> http://www.faqs.org/rfcs/rfc1321.html
            } 
            else{
            t += pad;
            }
        }
    }
    return t;
  };

/** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */

  async set(name, value) {
    
    const sha256KVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(this.data.kvsDeFato)))));
    if(sha256KVS !== this.secrets.hashKVS) throw "rollback attack!!!" // verificacao inicial do rollback attack

    const linkHMAC = bufferToString(await subtle.sign("HMAC", this.secrets.chavePrivadaHMAC, stringToBuffer(name)));
    
    //salt para tornar a senha encriptada de maneira única
    const saltDaSenha = getRandomBytes(16); 
    const senhaEmAES = encodeBuffer(await subtle.encrypt({name: "AES-GCM", iv: saltDaSenha},this.secrets.chavePrivadaAES, stringToBuffer(Keychain.preencheString(value, MAX_PASSWORD_LENGTH, "\0")))); // senha encriptada e em base64
    
    this.data.kvsDeFato[linkHMAC] = senhaEmAES;

    //salva o salt dessa informacao
    this.data.saltsKVS[linkHMAC] = saltDaSenha;

    //atualiza a garantia de integridade do KVS
    this.secrets.hashKVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(this.data.kvsDeFato)))));
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) { 
    const linkHMAC = bufferToString(await subtle.sign("HMAC", this.secrets.chavePrivadaHMAC, stringToBuffer(name)));

    if (!(linkHMAC in this.data.kvsDeFato)) return false;
    //apos verificar se realmente existe um cadastro de um link, remove ele do JSON encriptado
    delete this.data.kvsDeFato[linkHMAC]
    delete this.data.saltsKVS[linkHMAC];

    //atualiza a garantia de integridade do KVS
    this.secrets.hashKVS = bufferToString(await subtle.digest("SHA-256", stringToBuffer(encodeBuffer(JSON.stringify(this.data.kvsDeFato)))));
    
    return true;
  };
};

module.exports = { Keychain }
