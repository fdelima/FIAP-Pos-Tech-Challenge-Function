variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "fiap-pos-tech-function-rg"
}

variable "storage_account_name" {
  description = "Name of the Azure Storage Account"
  type        = string
  default     = "tokenvalidationfuncsa"
}

variable "service_plan_name" {
  description = "Name of the Azure Service Plan"
  type        = string
  default     = "token-validation-function-app-plan"
}

variable "azurerm_linux_function_app"{
    description = "Name of the Azure Function App"
    type        = string
    default     = "token-validation-function-app"
}