import 'package:flutter/material.dart';

import '../../core/api/gateway_api.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({required this.api, super.key});

  final GatewayBankingApi api;

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  final fullNameController = TextEditingController();
  final emailController = TextEditingController();
  final phoneController = TextEditingController();
  final addressController = TextEditingController();
  CustomerProfile? profile;
  bool loading = true;
  bool saved = false;

  @override
  void initState() {
    super.initState();
    load();
  }

  @override
  void dispose() {
    fullNameController.dispose();
    emailController.dispose();
    phoneController.dispose();
    addressController.dispose();
    super.dispose();
  }

  Future<void> load() async {
    final loaded = await widget.api.loadProfile();
    setState(() {
      profile = loaded;
      fullNameController.text = loaded.fullName;
      emailController.text = loaded.email;
      phoneController.text = loaded.phone;
      addressController.text = loaded.address;
      loading = false;
    });
  }

  Future<void> save() async {
    final current = profile;
    if (current == null) {
      return;
    }

    final updated = await widget.api.updateProfile(
      current.copyWith(
        fullName: fullNameController.text,
        email: emailController.text,
        phone: phoneController.text,
        address: addressController.text,
      ),
    );

    setState(() {
      profile = updated;
      saved = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Center(child: CircularProgressIndicator());
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text('Perfil', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 8),
        Text(
          'Customer registration data',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 16),
        TextField(
          controller: fullNameController,
          decoration: const InputDecoration(
            labelText: 'Nome',
            prefixIcon: Icon(Icons.person_outline),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: emailController,
          decoration: const InputDecoration(
            labelText: 'Email',
            prefixIcon: Icon(Icons.email_outlined),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: phoneController,
          decoration: const InputDecoration(
            labelText: 'Telefone',
            prefixIcon: Icon(Icons.phone_outlined),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: addressController,
          decoration: const InputDecoration(
            labelText: 'Endereco',
            prefixIcon: Icon(Icons.home_outlined),
          ),
        ),
        const SizedBox(height: 12),
        ListTile(
          leading: const Icon(Icons.badge_outlined),
          title: const Text('Documento'),
          subtitle: Text(profile!.documentNumber),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: save,
          icon: const Icon(Icons.save_outlined),
          label: const Text('Salvar perfil'),
        ),
        if (saved)
          const ListTile(
            leading: Icon(Icons.check_circle_outline),
            title: Text('Perfil atualizado'),
            subtitle: Text('PUT /profile via profile:write'),
          ),
      ],
    );
  }
}
