import cv2
import numpy as np
import hashlib

cam = cv2.VideoCapture(0)

def hash(s):
    hasher = hashlib.sha512()  # You can also use hashlib.sha256() or other available algorithms
    hasher.update(s.encode("utf-8"))
    return hasher.hexdigest()

def crop_frame(im):
    # return im[1079:1080, 1499:1500]
    return im

def im_to_string(im):
    s = np.array2string(im, separator="")
    return s

def gen_sec_hash():
    if cam.isOpened():
        works, frame = cam.read()
    else:
        exit(-1)

    while works:
        # frame = crop_frame(frame)
        works, frame = cam.read()
        s = im_to_string(frame)
        res = hash(s)
        yield res  # Yielding the hash result instead of printing
        key = cv2.waitKey(10)
        if key == 27:
            break

    cam.release()

if __name__ == '__main__':
    hash_generator = gen_sec_hash()
    while True:
        print(next(hash_generator))
        key = cv2.waitKey(10)
        if key == 27:  # Exit loop if the 'Esc' key is pressed
            break
