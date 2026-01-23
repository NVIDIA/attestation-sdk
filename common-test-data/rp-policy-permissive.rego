package policy
import future.keywords.every

default nv_match := false
nv_match {
  every result in input {
    result["x-nvidia-device-type"] == "gpu"
    result.secboot
    result.dbgstat == "disabled"
  }
}