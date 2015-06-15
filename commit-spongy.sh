#!/bin/bash 

branchName=`date +become-spongy_%Y-%m-%dT%H-%M-%S`

spongyScriptDir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

spongyScriptVersion=$( git --git-dir=$spongyScriptDir/.git describe --all --always --dirty --long )

git reset --hard

git clean -f -d

git checkout mending-bc

git checkout -b $branchName

becomeSpongyScript=$spongyScriptDir/become-spongy.sh

source $becomeSpongyScript

git add -A

git commit -m "Become spongy with become-spongy.sh" -m "Version: $echo $spongyScriptVersion" -m "https://github.com/rtyley/spongycastle/tree/spongy-scripts"