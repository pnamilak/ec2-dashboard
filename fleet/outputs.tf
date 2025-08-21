output "instance_ids" {
  value = [for i in aws_instance.win2022 : i.id]
}

output "instance_names" {
  value = [for i in aws_instance.win2022 : i.tags["Name"]]
}

output "name_to_id" {
  value = {
    for i in aws_instance.win2022 :
    i.tags["Name"] => i.id
  }
}

output "public_dns" {
  value = [for i in aws_instance.win2022 : i.public_dns]
}
