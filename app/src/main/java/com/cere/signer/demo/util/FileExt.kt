package com.cere.signer.demo.util

import com.cere.signer.demo.R
import com.cere.signer.demo.model.FileNode

fun FileNode.getIcon(): Int {
    if(this.isDirectory){

    }
    return R.drawable.ic_folder
}