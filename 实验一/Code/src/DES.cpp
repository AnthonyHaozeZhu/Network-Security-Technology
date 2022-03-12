#include "DES.h"

INT32 CDesOperate::HandleData(ULONG32 *left, ULONG8 choice) {
    uint32_t *right = &left[1] ;
    uint32_t tmpbuf[2] = { 0 }; 
    for (int  j = 0 ; j < 64 ; j++)
    {
        if (j < 32) 
        {
            if (pc_first[j] > 32)
            {
                if (*right & pc_by_bit[pc_first[j]-1])
                {
                    tmpbuf[0] |= pc_by_bit[j] ;
                }
            }
            else
            {
                if (*left & pc_by_bit[pc_first[j]-1])
                {
                    tmpbuf[0] |= pc_by_bit[j] ;
                }
            }
        }
        else
        {
            if (pc_first[j] > 32) {
                if (*right&pc_by_bit[pc_first[j]-1]) {
                    tmpbuf[1] |= pc_by_bit[j] ;
                }
            }
                else {
                    if (*left & pc_by_bit[pc_first[j]-1]) {
                        tmpbuf[1] |= pc_by_bit[j] ;
                    }
                }
        }
    }
    *left = tmpbuf[0];
    *right = tmpbuf[1];
    tmpbuf[0]=0;
    tmpbuf[1]=0;//重新置零！

    switch (choice)
    {
    case 0:
        for(int num=0;num<16;num++)//16轮迭代,加密
        {
            MakeData(left,right,(uint32_t)num);
        }
        break;
    case 1:
        for(int num=15;num>=0;num--)//16轮迭代，解密
        {
            MakeData(left,right,(uint32_t)num);
        }
        break;
    default:
        break;
    }

    INT32 temp;
    temp = *left;
    *left = *right;
    *right = temp;//交换左右！

    for (int j = 0 ; j < 64 ; j++) {
        if (j < 32 ) 
        {
            if ( pc_last[j] > 32) {
                if (*right & pc_by_bit[pc_last[j]-1]) {
                    tmpbuf[0] |= pc_by_bit[j] ;
                }
            }
            else {
                if (*left & pc_by_bit[pc_last[j]-1]) {
                    tmpbuf[0] |= pc_by_bit[j];
                }
            }
        }
        else {
            if (pc_last[j] > 32) {
                if (*right&pc_by_bit[pc_last[j]-1]) {
                    tmpbuf[1] |= pc_by_bit[j];
                }
            }
            else {
                if (*left&pc_by_bit[pc_last[j]-1]) {
                    tmpbuf[1] |= pc_by_bit[j] ;
                }
            }
        }
    }
    *left = tmpbuf[0] ;
    *right = tmpbuf[1];

    return true;
}

INT32 CDesOperate::MakeData(uint32_t *left ,uint32_t *right ,uint32_t number)//每一轮迭代中的除去初始置换和逆初始置换的中间操作
{
    uint32_t oldright=*right;
    uint32_t rexpbuf[8]={0};
    uint32_t exdes_P[2]={0};
    int j=0;
    for (int j = 0 ; j < 48 ; j++)
    {
        if ( j < 24 )
        {
            if ( *right&pc_by_bit[des_E[j]-1] )
            {
                exdes_P[0] |= pc_by_bit[j] ;
            } 
        } 
        else
        {
            if ( *right&pc_by_bit[des_E[j]-1] )
            {
                exdes_P[1] |= pc_by_bit[j-24] ;
            }
        }
    }
    for ( j = 0 ; j < 2 ; j++)
    { 
        exdes_P[j] ^= m_arrOutKey[number][j] ;
    }

    exdes_P[1] >>= 8 ;
    rexpbuf[7] = (uint8_t) (exdes_P[1]&0x0000003fL) ;
    exdes_P[1] >>= 6 ;
    rexpbuf[6] = (uint8_t) (exdes_P[1]&0x0000003fL) ;
    exdes_P[1] >>= 6 ;
    rexpbuf[5] = (uint8_t) (exdes_P[1]&0x0000003fL) ;
    exdes_P[1] >>= 6 ;
    rexpbuf[4] = (uint8_t) (exdes_P[1]&0x0000003fL) ;
    exdes_P[0] >>= 8 ;
    rexpbuf[3] = (uint8_t) (exdes_P[0]&0x0000003fL) ; 
    exdes_P[0] >>= 6 ;
    rexpbuf[2] = (uint8_t) (exdes_P[0]&0x0000003fL) ;
    exdes_P[0] >>= 6 ;
    rexpbuf[1] = (uint8_t) (exdes_P[0]&0x0000003fL) ;
    exdes_P[0] >>= 6 ;
    rexpbuf[0] = (uint8_t) (exdes_P[0]&0x0000003fL) ; 
    exdes_P[0] = 0 ;
    exdes_P[1] = 0 ;

    *right = 0 ;
    for ( j = 0 ; j < 7 ; j++)
    {
        *right |= des_S[j][rexpbuf[j]] ;
        *right <<= 4 ;
    }
    *right |= des_S[j][rexpbuf[j]] ;

    uint32_t datatmp = 0;
    for ( j = 0 ; j < 32 ; j++)
    {
        if ( *right&pc_by_bit[des_P[j]-1] )
        {
            datatmp |= pc_by_bit[j] ;
        }
    } 
    *right = datatmp ;

    *right ^= *left; 
    *left = oldright; 
    
    return true; 
}

CDesOperate::CDesOperate() {
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 2; j++) {
            m_arrOutKey[i][j] = 0;
        }
    }
    for(int i = 0; i < 2; i++) {
        m_arrBufKey[i] = 0;
    }
}

//DES密钥生成
/*
DES 密钥是一个 64bit 的分组，但是其中 8bit 是用于奇偶校验的，所以密钥的有效位只有 56bit，由这 56bit 生成 16 轮子密钥。
密钥生成，首先将有效的 56bit 进行置换选择，将结果等分为 28bit 的两个部分，再根据所在的迭代轮数进行循环左移，左移后将两个部分合并为 56 位的密钥，从中选取 48 位作 为此轮迭代的最终密钥，共生成 16 个 48 位的密钥。每一个密钥，分为两个 24 位的部分放 在一个 ULONG32 的二维数组中保存。
每一轮密钥生成，由 MakeKey 函数实现:
*/
INT32 CDesOperate::MakeKey(ULONG32 *keyleft, ULONG32 *keyright, ULONG32 number) {
    uint32_t tmpkey[2] ={0, 0};
    uint32_t *Ptmpkey = (uint32_t*)tmpkey; 
    uint32_t *Poutkey = (uint32_t*)&m_arrOutKey[number];
    uint32_t leftandtab[3]={0x0,0x80000000,0xc0000000};
    memset((uint8_t*)tmpkey,0,sizeof(tmpkey)); 
    Ptmpkey[0] = *keyleft&leftandtab[lefttable[number]]; 
    Ptmpkey[1] = *keyright&leftandtab[lefttable[number]]; 
    if (lefttable[number] == 1) {
        Ptmpkey[0] >>= 27;
        Ptmpkey[1] >>= 27;
    }
    else {
        Ptmpkey[0] >>= 26;
        Ptmpkey[1] >>= 26; 
    }
    Ptmpkey[0] &= 0xfffffff0;
    Ptmpkey[1] &= 0xfffffff0;
    *keyleft <<= lefttable[number] ;
    *keyright <<= lefttable[number] ;
    *keyleft |= Ptmpkey[0] ;
    *keyright |= Ptmpkey[1] ; 
    Ptmpkey[0] = 0;
    Ptmpkey[1] = 0;
    for (int j = 0 ; j < 48 ; j++) {
        if (j < 24) {
            if ( *keyleft&pc_by_bit[keychoose[j]-1]) {
                Poutkey[0] |= pc_by_bit[j] ;
            } 
        } 
        else {
            /*j>=24*/ 
            if ( *keyright&pc_by_bit[(keychoose[j]-28)]) {
                Poutkey[1] |= pc_by_bit[j-24] ;
            }
        }
    }
    return SUCCESS;
}


INT32 CDesOperate::Decry(char* pCipher, int nCipherBufferLength, char *pPlaintextBuffer, 
  int &nPlaintextBufferLength, char *pKey,int nKeyLength)//解密函数
  {
    if(nKeyLength != 8) {
        return 0;
    }
    MakeFirstKey((uint32_t *)pKey);

    memset(pPlaintextBuffer,0,nPlaintextBufferLength);
    uint32_t *pOutPutSpace = (uint32_t *)pPlaintextBuffer;
    uint32_t * pSource = (uint32_t *)pCipher;

    uint32_t gp_msg[2] = {0,0};
    for (int i=0;i<(nCipherBufferLength/8);i++) {
        gp_msg[0] = pSource [2*i];
        gp_msg[1] = pSource [2*i+1];
        HandleData(gp_msg,(uint8_t)1);
        pOutPutSpace[2*i] = gp_msg[0];
        pOutPutSpace[2*i+1] = gp_msg[1];
    }
    return true;
  }

//DES 加密运算
/*
DES 的加密运算也分为 16 轮迭代。
首先将明文分为 64bit 的数据块，不够 64 位的用 0 补齐。每一轮中，对每一个 64bit 的数据块，首先进行初始换位，并将数据块分为 32bit 的两部分:


经过初始置换并且分组之后，将进行 DES 加密算法的核心部分。
首先，保持左部不变，将右部由 32 位扩展成为 48 位，分别存在两个 ULONG32 类型的 变量里，每个占 24bit。

在将右部扩展成为 48 位之后，与该轮的密钥进行异或操作，由于 48 位分在一个ULONG32 数组中的两个元素中，故要进行两次异或。

在异或操作完成之后，对新的 48 位进行压缩操作，即 S 盒。 将其每取 6 位，进行一次操作。


8个6bit的数据存在ULONG rexpbuf[8]中，然后进行数据压缩操作，每一个6位经过 运算之后输出 4 位，故最终输出的是 32 位的压缩后的数据。

对新的 32bit 数据，进行一次置换操作。

再把左右部分进行异或作为右半部分，最原始的右边作为左半部分，即将完成一轮完整 的加密操作。


最后进行逆初始置换，完成一轮完整的加密操作。

将上述运算整合在一起，可以封装成一个加密函数，以便于调用，其中 pPlaintext 为明
*/

INT32 CDesOperate::Encry(char *pPlaintext, int nPlaintextLength, char *pCipherBuffer, int &nCipherBufferLength, char *pKey, int nKeyLength) {
    //首先检查初始密钥长度，若正确，则创建 16 轮迭代的密钥。
    if(nKeyLength != 8) {
        return 0;
    }
    MakeFirstKey((uint32_t *)pKey);

    //由于加解密均要以 32bit 为单位进行操作，故需要计算相关参数，以确定加密的循环次数以及密文缓冲区是否够用，确定后将需要加密的明文格式化到新分配的缓冲区内。
    int nLenthofLong = ((nPlaintextLength+7)/8)*2;
    if(nCipherBufferLength<nLenthofLong*4) {
        //out put buffer is not enough
        nCipherBufferLength=nLenthofLong*4;
    }
    memset(pCipherBuffer,0,nCipherBufferLength);
    uint32_t *pOutPutSpace = (uint32_t *)pCipherBuffer;
    uint32_t * pSource;
    if(nPlaintextLength != sizeof(uint32_t)*nLenthofLong) {
        pSource= new uint32_t[nLenthofLong];
        memset(pSource,0,sizeof(uint32_t)*nLenthofLong);
        memcpy(pSource,pPlaintext,nPlaintextLength);
    }
    else {
        pSource= (uint32_t *)pPlaintext;
    }

    //开始对明文进行加密，加密后将之前分配的缓冲区从内存中删除。
    uint32_t gp_msg[2] = {0,0};
    for (int i=0;i<(nLenthofLong/2);i++)
    {
        gp_msg[0] = pSource [2*i];
        gp_msg[1] = pSource [2*i+1];
        HandleData(gp_msg,(uint8_t)0);
        pOutPutSpace[2*i] = gp_msg[0];
        pOutPutSpace[2*i+1] = gp_msg[1];
    }
    if(pPlaintext!=(char *) pSource)
    {
        delete []pSource;
    }
    
    return SUCCESS;
}

//最后需要说明，上述函数为一次完整的加密流程，解密流程与加密流程基本一致，仍为 先进行初始置换，最后进行逆置换，中间 16 轮利用 16 个密钥的迭代加密，唯一不同的地方 就是所生成的 16 个密钥的使用顺序，加密运算与解密运算的密钥使用顺序正好相反。


INT32 CDesOperate::MakeFirstKey(ULONG32 *keyP) {
    uint32_t tempKey[2]={0};
    uint32_t*pFirstKey=(uint32_t*)m_arrBufKey;
    uint32_t*pTempKey=(uint32_t*)tempKey;
    memset((uint8_t*)m_arrBufKey, 0, sizeof(m_arrBufKey));
    memcpy((uint8_t*)&tempKey, (uint8_t*)keyP,8);
    memset((uint8_t*)m_arrOutKey, 0, sizeof(m_arrOutKey));
    for(int j = 0; j < 28; j++) {                                                        
        //循环28次   64---->56     但还是要用2个32位来存储
        if(keyleft[j] > 32)
        {                                                    
            //第一个32位
            if(pTempKey[1]&pc_by_bit[keyleft[j]-1]) {                                                
                //第一次出现这种pc_by_bit[],此后涉及到选取特定的位都将用到
                pFirstKey[0] |= pc_by_bit[j];                                            
                //其实原理很简单  先判断一下要选取的bit数组对应的位是否为1
            }
            //通过与上0x80000000(1000 0000 0000 0000...)等只有一bit为1的数即可判断
        }                                                   
        //再将相应的位 置1通过或上0x80000000(1000 0000 0000 0000...)等只有一bit为1的数即可
        else {
            if(pTempKey[0] & pc_by_bit[keyleft[j] - 1])
            {
                pFirstKey[0] |= pc_by_bit[j];
            }
        }
        if(keyright[j] > 32) {                                                    
            //第二个32位
            if(pTempKey[1] & pc_by_bit[keyright[j] - 1]) {
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
        else {
            if(pTempKey[0] & pc_by_bit[keyright[j] - 1])
            {
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
    }
    for(int j = 0; j < 16; j++) {
        MakeKey(&pFirstKey[0],&pFirstKey[1],j);            //firstKey已形成，循环调用oneStepOfMakeSubKe()形成子秘钥
    }
    return SUCCESS;
    
}