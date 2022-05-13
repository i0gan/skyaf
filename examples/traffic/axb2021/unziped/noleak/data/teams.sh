for f in `find . -name "*.log"` 
do 
   #echo $f 
   awk 'NR>=4 && NR<=6' $f
done

