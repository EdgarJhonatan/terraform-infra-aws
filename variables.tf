variable "bucket_name" {
  type        = string
  description = "Nombre base del bucket"
}

variable "prefix_resource_name" {
  type        = string
  description = "Prefijo que se agrega al bucket"
}

variable "tags" {
  type        = map(string)
  description = "Etiquetas para aplicar al bucket"
}
