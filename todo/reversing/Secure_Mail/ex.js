function find(val) {
    let format = /^([0-9]{2})(0[1-9]|1[1-2])(0[1-9]|[1,2][0-9]|3[1,2])$/;
    if (format.test(val))
        _0x9a220(val);
    else
        return;
}