from bitstring import pack, BitArray

from algorithm.util import galNI, sbox_1, sbox_2, sbox_3, sbox_4

__author__ = 'Iurii Sergiichuk <iurii.sergiichuk@gmail.com>'


class MasterKey(object):
    def __init__(self, master_key_hex_string="0x3cc849279ba298b587a34cabaeffc5ecb3a044bbf97c516fab7ede9d1af77cfa"):
        self.key = BitArray(master_key_hex_string)
        self.session_keys_amount = 8
        self.current_cycle_index = 0
        self.master_key_round_shift_bits = 24

    def get_round_keys(self):
        """


        :return: list of round keys
        :rtype: list[RoundKey]
        """
        if self.current_cycle_index:
            round_master_key = self.key.copy()
            round_master_key.ror(self.master_key_round_shift_bits * self.current_cycle_index)
        else:
            round_master_key = self.key.copy()
        round_keys = []
        round_key_size = round_master_key.length / self.session_keys_amount
        for key_index in range(0, self.session_keys_amount):
            round_key = round_master_key[key_index * round_key_size:key_index * round_key_size + round_key_size]
            round_keys.append(RoundKey(round_key))
        if self.current_cycle_index < 8:
            self.current_cycle_index += 1
        else:
            self.current_cycle_index = 0
        return round_keys


class RoundKey(object):
    def __init__(self, key):
        """

        :param key: round key
        :type key: BitArray
        """
        self.key = key

    def set_round_key(self, key):
        self.key = key


class Message(object):
    def __init__(self, message_bit_array=BitArray(length=256)):
        """

        :param message_bit_array: message BitArray
        :type message_bit_array: BitArray
        """
        self.message_block_amount = 8
        self.normal_message_bits_amount = 256
        self.message_bit_array = message_bit_array
        self.message = self.message_bit_array.tobytes()
        self._normalize_message()

    @classmethod
    def get_message_from_message_blocks(cls, message_blocks):
        message_bit_array = BitArray()
        for message_block in message_blocks:
            message_bit_array.append(message_block.message_block)
        return Message(message_bit_array)

    def set_message_as_string(self, message_string):
        self.message = message_string
        self.message_bit_array = BitArray(self.message_to_hex(message_string))

    def message_to_hex(self, message_string):
        return '0x' + ''.join(x.encode('hex') for x in message_string)

    def _normalize_message(self):
        if self.message_bit_array.length > self.normal_message_bits_amount:
            self._trim_message()

    def _trim_message(self):
        self.message_bit_array = self.message_bit_array[0:self.normal_message_bits_amount]

    def get_message_blocks(self):
        message_bit_array = self.message_bit_array.copy()
        message_blocks = []
        message_block_size = self.normal_message_bits_amount / self.message_block_amount

        padding_blocks_amount = (
                                    self.normal_message_bits_amount - message_bit_array.length) / message_block_size
        padding_bits_amount = (self.normal_message_bits_amount - message_bit_array.length) % message_block_size
        if padding_bits_amount != 0:
            padding_block = BitArray('0b' + ''.join('0' for x in range(0, padding_bits_amount)))
            message_bit_array.prepend(padding_block)

        for padding_block_index in range(0, padding_blocks_amount):
            message_block = BitArray('0b00000000000000000000000000000000')
            message_blocks.append(MessageBlock(message_block))

        for message_block_index in range(0, self.message_block_amount - padding_blocks_amount):
            message_block = message_bit_array[
                            message_block_index * message_block_size:message_block_index * message_block_size + message_block_size]
            message_blocks.append(MessageBlock(message_block))
        return message_blocks


    def __unicode__(self):
        return self.message


    def __str__(self):
        return self.__unicode__()


class MessageBlock(object):
    def __init__(self, message_block):
        """

        :param message_block: message block
        :type message_block: BitArray
        """
        self.message_block = message_block


class Crypter(object):
    def __init__(self, master_key, message):
        """

        :param master_key: master key
        :type master_key: MasterKey
        :param message: message
        :type message: Message
        """
        self.master_key = master_key
        self.message = message
        self._crypt_message = None
        self._current_round = 1
        self._rounds_amount = 8

    def encrypt(self):
        self._crypt_message = self._one_round_crypt(self.message)
        while self._current_round != self._rounds_amount:
            self._crypt_message = self._one_round_crypt(self._crypt_message)
        return self._crypt_message

    def _one_round_crypt(self, message):
        round_keys = self.master_key.get_round_keys()
        message_blocks = message.get_message_blocks()
        crypt_block_list = []

        for round_key, message_block in zip(round_keys, message_blocks):
            crypt_block = round_key.key ^ message_block.message_block
            crypt_block_list.append(MessageBlock(crypt_block))
        # XOR first block with others
        for crypt_block_index in range(1, len(crypt_block_list)):
            crypt_block_list[0].message_block ^= crypt_block_list[crypt_block_index].message_block

        # make first block SL transformation
        crypt_block_list[0] = self.sl_transformation(crypt_block_list[0])
        # make SL transformation with XOR to next block
        for crypt_block_index in range(1, len(crypt_block_list)):
            crypt_xored_with_previous_block = MessageBlock(
                crypt_block_list[crypt_block_index].message_block ^ crypt_block_list[
                    crypt_block_index - 1].message_block)
            crypt_block_list[crypt_block_index] = self.sl_transformation(crypt_xored_with_previous_block)
        for crypt_block_index in range(0, len(crypt_block_list) - 1):
            crypt_block_list[crypt_block_index].message_block ^= crypt_block_list[
                len(crypt_block_list) - 1].message_block

        if self._current_round < 8:
            self._current_round += 1
        return Message.get_message_from_message_blocks(crypt_block_list)

    def sl_transformation(self, crypt_block):
        """

        :param crypt_block: crypt block
        :type crypt_block: MessageBlock
        """
        s_0 = sbox_1[crypt_block.message_block[0:8].int]
        s_1 = sbox_2[crypt_block.message_block[8:16].int]
        s_2 = sbox_3[crypt_block.message_block[16:24].int]
        s_3 = sbox_4[crypt_block.message_block[24:32].int]
        crypt_block_result = self.mdr_transformation(pack('uint:8, uint:8, uint:8, uint:8', s_0, s_1, s_2, s_3))
        return MessageBlock(crypt_block_result)

    def mdr_transformation(self, s_block):
        """

        :param s_block: s-block
        :type s_block: BitArray
        """
        mdr_0 = s_block[0:8].int
        mdr_1 = s_block[8:16].int
        mdr_2 = s_block[16:24].int
        mdr_3 = s_block[24:32].int
        g0, g1, g2, g3 = galNI
        result_0 = g0[mdr_0] ^ g1[mdr_1] ^ g2[mdr_2] ^ g3[mdr_3]
        result_1 = g3[mdr_0] ^ g0[mdr_1] ^ g1[mdr_2] ^ g2[mdr_3]
        result_2 = g2[mdr_0] ^ g3[mdr_1] ^ g0[mdr_2] ^ g1[mdr_3]
        result_3 = g1[mdr_0] ^ g2[mdr_1] ^ g3[mdr_2] ^ g0[mdr_3]
        return pack('uint:8, uint:8, uint:8, uint:8', result_0, result_1, result_2, result_3)