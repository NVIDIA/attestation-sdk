package policy

import future.keywords.every

default nv_match := false

nv_match {
    input.ear_status == "affirming"
    is_object(input.submods)
    count(input.submods) > 0
    every _, submod in input.submods {
        submod.ear_status == "affirming"
    }
}
