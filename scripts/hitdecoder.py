from struct import pack, unpack
from hexdump import hexdump
from binascii import hexlify, unhexlify, crc32
from os import path, mkdir
from glob import glob

def xtea_encrypt(key, data):
	real_sz = len(data)
	data += b'\x00' * (8 - real_sz % 8)
	comp_sz = real_sz // 4
	result = b''
	i = 0
	DELTA = 0x9E3779B9
	key = unpack('IIII', key)
	while i < comp_sz:
		v0, v1 = unpack('II', data[0:8])
		data = data[8:]
		s = 0x0
		for rnd in range(0x20):
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (key[s & 0x3] + s)
			v0 &= 0xffffffff

			s += DELTA
			s &= 0xffffffff

			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (key[s >> 0xb & 0x3] + s)
			v1 &= 0xffffffff

		result += pack('II', v0 & 0xffffffff, v1 & 0xffffffff)
		i += 2
	return result

def xtea_decrypt(key, data):
	real_sz = len(data)
	comp_sz = real_sz // 4
	data += b'\x00' * (8 - real_sz % 8)
	result = b''
	i = 0
	DELTA = 0xC6EF3720
	key = unpack('IIII', key)
	while i < comp_sz:
		v0, v1 = unpack('II', data[0:8])
		data = data[8:]
		s = DELTA
		for rnd in range(0x20):
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (key[s >> 0xb & 0x3] + s)
			v1 &= 0xffffffff

			s -= 0x9E3779B9
			s &= 0xffffffff

			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (key[s & 0x3] + s)
			v0 &= 0xffffffff

		result += pack('II', v0 & 0xffffffff, v1 & 0xffffffff)
		i += 2
	return result[:real_sz]

def xor(data, key):
	res = bytearray(data)
	d_sz = len(data)
	k_sz = len(key)
	i = 0
	while i < d_sz:
		res[i] ^= key[i % k_sz]
		i += 1
	return res

KEY = unhexlify('377752539E490675E3AE39BD68729EA5')


class HitmanTextFile:
	KEY = unhexlify('8252F93019C4481F48855F296D36782A')
	MAGIC = unhexlify('223D6F9AB3F8FEB661D9CC1C62DE8341')

	@staticmethod
	def encrypt(fname, data):
		csum = crc32(data)
		open(fname, 'wb').write(HitmanTextFile.MAGIC + pack('I', csum) + xtea_encrypt(HitmanTextFile.KEY, data))

	def decrypt(fname):
		data = open(fname, 'rb').read()
		if data[0x00:0x10] != HitmanTextFile.MAGIC:
			raise Exception('Invalid magic')
		decrypted_data = xtea_decrypt(HitmanTextFile.KEY, data[0x14:]).strip(b'\x00')
		csum = unpack('I', data[0x10:0x14])[0]
		comp_csum = crc32(decrypted_data)
		if csum != comp_csum:
			raise Exception('Invalid CRC32: expected=%08x - computed=%08x' % (csum, comp_csum))
		return decrypted_data

class HitmanRpkg:
	MAGIC = unpack('I', b'GKPR')[0] # This magic is actually ignored by the game
	FILE_KEY = pack('Q', 0xAB4C72D39CA645DC)

	class File:
		def __init__(self, fnv_hash, offset, size, file):
			self.hash = fnv_hash
			self.offset = offset
			self.size = size & ~0x80000000
			self.flag = True if size & 0x80000000 else False
			self.file = file

		def __str__(self):
			return 'hash=0x%016x, offset=0x%016x, size=0x%08x, flag=%s' % (self.hash, self.offset, self.size, self.flag)

		def decrypt_data(self):
			self.file.seek(self.offset)
			encrypted_data = self.file.read(self.size)
			return xor(encrypted_data, HitmanRpkg.FILE_KEY)


	class Box:
		def __init__(self, tag, data_size, unk0, unk1, unk2, unk3, data):
			self.tag = tag
			self.data_size = data_size
			self.data = data
			self.unk0 = unk0
			self.unk1 = unk1
			self.unk2 = unk2
			self.unk3 = unk3

		def __str__(self):
			hdr = 'tag=%s, data_size=%08x, unk=%08x,%08x,%08x,%08x' % (self.tag, self.data_size, self.unk0, self.unk1, self.unk2, self.unk3)
			hsh = '\nhashed_filename=' + ','.join([ '0x%016x' % h for h in self.get_file_hashes() ])
			return hdr + hsh

		def get_file_hashes(self):
			if self.data_size == 0x0 or len(self.data) == 0x0:
				return []
			res = []
			files_hash_no = unpack('I', self.data[0x0:0x4])[0] & ~0x80000000
			return list(unpack('Q' * files_hash_no, self.data[0x4:0x4 + 0x8 * files_hash_no]))

	def __init__(self, folder):
		self.files = []
		self.boxes = []
		self.hashes = []

		for pkg in glob(folder + '/*.rpkg'):
			is_patch = True if 'patch' in pkg else False
			f = open(pkg, 'rb')
			magic, offset_of_files, size_of_files, offset_of_boxes, size_of_boxes = self._decode_header(f, is_patch)
			if magic != HitmanRpkg.MAGIC:
				print('File %s is not a RPKG: %08x' % magic)
			self._decode_files(f, offset_of_files, size_of_files)
			self._decode_boxes(f, offset_of_boxes, size_of_boxes)
			if is_patch:
				f.seek(0x10)
				offset_of_hashes, size_of_hashes = 0x14, unpack('I', f.read(0x4))[0] * 0x8
				self._decode_hashes(f, offset_of_hashes, size_of_hashes)

	def _decode_header(self, f, is_patch):
		if is_patch:
			magic, number_of_files, size_of_files, size_of_boxes, number_of_hashes = unpack('IIIII', f.read(0x14))
			offset_of_files = number_of_hashes * 8
			offset_of_boxes = offset_of_files + size_of_files
		else:
			magic, number_of_files, size_of_files, size_of_boxes = unpack('IIII', f.read(0x10))
			offset_of_files = 0x10
			offset_of_boxes = offset_of_files + size_of_files

		return magic, offset_of_files, size_of_files, offset_of_boxes, size_of_boxes


	def _decode_files(self, f, offset_of_files, size_of_files):
		f.seek(offset_of_files)
		while offset_of_files < size_of_files:
			fnv_hash, offset, size = unpack('QQI', f.read(0x14))
			file = HitmanRpkg.File(fnv_hash, offset, size, f)
			self.files.append(file)
			offset_of_files += 0x14

	def _decode_boxes(self, f, offset_of_boxes, size_of_boxes):
		f.seek(offset_of_boxes)
		while offset_of_boxes < size_of_boxes:
			tag, data_size, unk0, unk1, unk2, unk3 = unpack('IIIIII', f.read(0x18))
			data = f.read(data_size)
			box = HitmanRpkg.Box(pack('>I', tag), data_size, unk0, unk1, unk2, unk3, data)
			self.boxes.append(box)
			offset_of_boxes += 0x18 + data_size

	def _decode_hashes(self, f, offset_of_hashes, size_of_hashes):
		f.seek(offset_of_hashes)
		while offset_of_hashes < size_of_hashes:
			self.hashes.append(unpack('Q', f.read(0x8))[0])
			offset_of_hashes += 0x8

	def list_files(self):
		for r in self.resource_files:
			print(r)

	def list_boxes(self):
		for b in self.boxes:
			print(b)

	def extract_one_file(self, filename):
		# TODO handle clear filename
		if type(filename) == bytes:
			hashed_filename = unpack('Q', filename)[0]
		elif type(filename) == str:
			raise Exception('FNV hash is not yet supported')
		elif type(filename) == int:
			hashed_filename = filename
		else:
			raise Exception('Unsupported type of filename')
		for f in self.files:
			if f.hash == hashed_filename:
				return f
		raise Exception('File 0x%016x not found' % hashed_filename)


if __name__ == '__main__':

	rpkg = HitmanRpkg('.')

	for b in rpkg.boxes:
		for h in b.get_file_hashes():
			try:
				f = rpkg.extract_one_file(h)
			except:
				continue
			print(b)
			print(f)
			hexdump(f.decrypt_data())

	fname = '../Retail/thumbs.dat'
	decrypted = HitmanTextFile.decrypt(fname)
	print(decrypted.decode())
	# open('../Retail/thumbs.dat.txt', 'w').write(decrypted.decode())

	# d = open('../Retail/thumbs_dbg.dat.txt', 'r').read()
	# HitmanTextFile.encrypt(fname, bytes(d, 'latin1'))