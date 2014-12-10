# coding=utf-8
from bitstring import BitArray

from algorithm.implementation import MasterKey, Message, Crypter


def compare_bit_arrays(bit_array_1, bit_array_2):
    """

    :param bit_array_1:
    :type bit_array_1: BitArray
    :param bit_array_2:
    :type bit_array_2: BitArray
    """
    if bit_array_1.length != bit_array_2.length:
        return False, -1
    equal_bits = 0
    for bit_array_1_element, bit_array_2_element in zip(bit_array_1.bin, bit_array_2.bin):
        if bit_array_1_element == bit_array_2_element:
            equal_bits += 1
    if equal_bits != 0:
        return False, equal_bits
    return True, 0


def make_avalanche_effect_test(message, encrypted_message):
    message_bit_array_len = len(message.message_bit_array)
    total_changed_bits_amount = 0
    for changed_bit_index in range(1, message_bit_array_len):
        m_k = MasterKey()
        one_bit_changed_message = message.message_bit_array.copy()
        one_bit_changed_message.invert(changed_bit_index)

        changed_message = Message(one_bit_changed_message)
        changed_message_crypter = Crypter(master_key=m_k, message=changed_message)
        encrypted_changed_message = changed_message_crypter.encrypt()

        print encrypted_changed_message
        compare_result, equal_bits_amount = compare_bit_arrays(
            encrypted_message.message_bit_array, encrypted_changed_message.message_bit_array)
        total_changed_bits_amount += equal_bits_amount
        print "Аvalanche effect test. %d bit changed. Crypted messages are equal? %r. Equal bits amount = %d" % (
            changed_bit_index, compare_result, equal_bits_amount)
    average_avalanche_effect = total_changed_bits_amount * 1.0 / message_bit_array_len
    print "Average avalanche effect test. Average equal bits amount = %d" % average_avalanche_effect


def main():
    master_key = "0x3cc849279ba298b587a34cabaeffc5ecb3a044bbf97c516fab7ede9d1af77cfa"
    k = BitArray(master_key)
    m_k = MasterKey()
    message = Message()
    message_string = "GujTMw57QnjDS314bmOtoAnLy4jTg8rq"
    message.set_message_as_string(message_string)

    print "Message: %s" % message_string

    crypted = Crypter(master_key=m_k, message=message)
    encrypted_message = crypted.encrypt()

    print encrypted_message
    make_avalanche_effect_test(message, encrypted_message)
    # m_k = MasterKey()
    # one_bit_changed_message = message.message_bit_array.copy()
    # one_bit_changed_message.invert(35)
    #
    # changed_message = Message(one_bit_changed_message)
    # changed_message_crypter = Crypter(master_key=m_k, message=changed_message)
    # encrypted_changed_message = changed_message_crypter.encrypt()
    #
    # print encrypted_changed_message
    #
    # print "Аvalanche effect test. One bit changed. Crypted messages are equal? %r. Equal bits amount = %d" % compare_bit_arrays(
    # encrypted_message.message_bit_array, encrypted_changed_message.message_bit_array)


if __name__ == '__main__':
    main()


