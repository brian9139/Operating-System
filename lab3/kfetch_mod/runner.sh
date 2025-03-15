#!/bin/bash

# start script
user_code=$1
output=$2

testcase=( " "
			"-c"
			"-m"
			"-n"
			"-p"
			"-r"
			"-u"
			"-n -p"
			"-c -m"
			"-r -u"
			"-n -c -r"
			"-p -m -u -n"
			" "
			"-a"
			" ")

touch $output
case_count=${#testcase[@]}
for (( j = 0; j < $case_count; j += 1 ));
do
    case=${testcase[$j]}
    echo "Running testcase" $j ":" $case
    echo "---------------------------------------- [" $case "]" >> $output
    sudo $user_code $case >> $output
    echo "---------------------------------------- [" $case "]" >> $output
done

