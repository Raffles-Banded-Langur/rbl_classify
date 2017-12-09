import random;
import numpy as np; 

def check_randomness( max_range  ):
 image_1_id_list = [];
 image_2_id_list = [];
 for x in range(0, 10000):
  image_ids = list(range(1, int(max_range)+1));

  list_image_random_ids = random.sample(set(image_ids), 2);

  image_1_id  = list_image_random_ids[0];
  image_2_id  = list_image_random_ids[1];
  
  #print image_1_id;
  #print image_2_id;
  image_1_id_list.append(image_1_id);
  image_2_id_list.append(image_2_id);
 
 #print image_1_id_list;
 #print image_2_id_list;
 
 #result = 1 - spatial.distance.cosine(image_1_id_list, image_2_id_list);
 #from itertools import groupby
 #result = [len(list(group)) for key, group in groupby(image_1_id_list)]
 #print result;
 
 #image1_unique_len = len(set(image_1_id_list));
 #image2_unique_len = len(set(image_2_id_list));
 
 print len(np.unique(image_1_id_list));
 print len(np.unique(image_2_id_list));
 
 return;

check_randomness (1000)
